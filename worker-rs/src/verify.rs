// Aptos permission verification

use anyhow::{anyhow, Result};
use sha3::{Digest, Sha3_256};

use crate::{aptos_rpc::AptosRpc, types::AptosProofOfPermission};

/// Verify Aptos permission: signature check + auth key check + view function check
pub async fn verify_aptos_permission(
    rpc: &AptosRpc,
    chain_id: u8,
    module_addr: &[u8; 32],
    module_name: &str,
    function_name: &str,
    domain: &[u8],
    proof: &AptosProofOfPermission,
) -> Result<()> {
    let pretty_msg = to_pretty_message(chain_id, module_addr, module_name, function_name, domain);

    let (sig_result, auth_result, perm_result) = tokio::join!(
        verify_signature(proof, &pretty_msg),
        check_auth_key(rpc, proof),
        check_permission(rpc, module_addr, module_name, function_name, &proof.user_addr, domain),
    );

    sig_result.map_err(|e| anyhow!("signature check failed: {}", e))?;
    auth_result.map_err(|e| anyhow!("auth key check failed: {}", e))?;
    perm_result.map_err(|e| anyhow!("permission check failed: {}", e))?;

    Ok(())
}

/// Build toPrettyMessage() matching the TypeScript SDK output
pub fn to_pretty_message(
    chain_id: u8,
    module_addr: &[u8; 32],
    module_name: &str,
    function_name: &str,
    domain: &[u8],
) -> String {
    let module_addr_hex = hex::encode(module_addr);
    let domain_hex = hex::encode(domain);
    format!(
        "\ncontractId:\n  scheme: aptos\n  inner:\n      chainId: {}\n      moduleAddr: 0x{}\n      moduleName: {}\n      functionName: {}\ndomain: 0x{}",
        chain_id, module_addr_hex, module_name, function_name, domain_hex
    )
}

async fn verify_signature(proof: &AptosProofOfPermission, pretty_msg: &str) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Check fullMessage contains prettyMsg or its hex encoding
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());
    let contains_pretty = proof.full_message.contains(pretty_msg);
    let contains_hex = proof.full_message.contains(&pretty_msg_hex);
    if !contains_pretty && !contains_hex {
        return Err(anyhow!("fullMessage does not contain expected domain info"));
    }

    // Verify Ed25519 signature over UTF-8 bytes of full_message
    match proof.pk_scheme {
        0 => {
            // Ed25519
            let pk_bytes: [u8; 32] = proof.pubkey_bytes.clone().try_into()
                .map_err(|_| anyhow!("invalid pubkey length"))?;
            let vk = VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| anyhow!("invalid pubkey: {}", e))?;
            let sig_bytes: [u8; 64] = proof.sig_bytes.clone().try_into()
                .map_err(|_| anyhow!("invalid sig length"))?;
            let sig = Signature::from_bytes(&sig_bytes);
            use ed25519_dalek::Verifier;
            vk.verify(proof.full_message.as_bytes(), &sig)
                .map_err(|e| anyhow!("Ed25519 verification failed: {}", e))?;
        }
        1 => {
            // AnyPublicKey with Ed25519 inner key
            if proof.any_pk_inner_variant == Some(0) {
                // Ed25519 inner key
                let pk_bytes: [u8; 32] = proof.pubkey_bytes.clone().try_into()
                    .map_err(|_| anyhow!("invalid inner pubkey length"))?;
                let vk = VerifyingKey::from_bytes(&pk_bytes)
                    .map_err(|e| anyhow!("invalid inner pubkey: {}", e))?;
                let sig_bytes: [u8; 64] = proof.sig_bytes.clone().try_into()
                    .map_err(|_| anyhow!("invalid sig length"))?;
                let sig = Signature::from_bytes(&sig_bytes);
                use ed25519_dalek::Verifier;
                vk.verify(proof.full_message.as_bytes(), &sig)
                    .map_err(|e| anyhow!("Ed25519 verification failed: {}", e))?;
            } else {
                return Err(anyhow!("Unsupported AnyPublicKey inner variant: {:?}", proof.any_pk_inner_variant));
            }
        }
        _ => return Err(anyhow!("Unsupported pk_scheme: {}", proof.pk_scheme)),
    }
    Ok(())
}

async fn check_auth_key(rpc: &AptosRpc, proof: &AptosProofOfPermission) -> Result<()> {
    let user_addr = format!("0x{}", hex::encode(&proof.user_addr));
    let account = rpc.get_account(&user_addr).await
        .map_err(|e| anyhow!("failed to get account: {}", e))?;

    let on_chain_hex = account.authentication_key.trim_start_matches("0x").to_lowercase();

    // Compute expected auth key
    let expected = match proof.pk_scheme {
        0 => {
            // Ed25519: sha3_256(pubkey_32_bytes || 0x00)
            let pk_bytes: &[u8; 32] = proof.pubkey_bytes.as_slice().try_into()
                .map_err(|_| anyhow!("invalid pubkey length"))?;
            let mut hasher = Sha3_256::new();
            hasher.update(pk_bytes);
            hasher.update([0x00u8]);
            let hash: [u8; 32] = hasher.finalize().into();
            hex::encode(hash)
        }
        1 => {
            // AnyPublicKey (SingleKey scheme = 0x03):
            // sha3_256(anyPublicKey.bcsToBytes() || 0x03)
            // bcsToBytes = ULEB128(variant) + ULEB128(len) + inner_bytes
            let mut hasher = Sha3_256::new();
            hasher.update(&proof.any_pk_inner_bytes);
            hasher.update([0x03u8]);
            let hash: [u8; 32] = hasher.finalize().into();
            hex::encode(hash)
        }
        _ => return Err(anyhow!("Unsupported pk_scheme for auth key: {}", proof.pk_scheme)),
    };

    if on_chain_hex != expected {
        return Err(anyhow!("auth key mismatch: on-chain={}, expected={}", on_chain_hex, expected));
    }
    Ok(())
}

async fn check_permission(
    rpc: &AptosRpc,
    module_addr: &[u8; 32],
    module_name: &str,
    function_name: &str,
    user_addr: &[u8; 32],
    domain: &[u8],
) -> Result<()> {
    use serde_json::json;
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(module_addr), module_name, function_name
    );
    let user_addr_str = format!("0x{}", hex::encode(user_addr));
    let domain_hex = format!("0x{}", hex::encode(domain));

    let result = rpc.view(&func, &[], &[json!(user_addr_str), json!(domain_hex)]).await
        .map_err(|e| anyhow!("view function call failed: {}", e))?;

    let returned = result.get(0)
        .ok_or_else(|| anyhow!("empty view result"))?;

    let is_true = returned.as_bool() == Some(true)
        || returned.as_str() == Some("true");

    if !is_true {
        return Err(anyhow!("permission denied: view returned {:?}", returned));
    }
    Ok(())
}
