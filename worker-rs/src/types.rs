// Types parsed from BCS wire format

use crate::bcs::BcsReader;
use anyhow::{anyhow, Result};

#[derive(Debug, Clone)]
pub struct AptosContractId {
    pub chain_id: u8,
    pub module_addr: [u8; 32],
    pub module_name: String,
    pub function_name: String,
}

#[derive(Debug, Clone)]
pub struct AptosProofOfPermission {
    pub user_addr: [u8; 32],
    pub pk_scheme: u8,
    pub pubkey_bytes: Vec<u8>,     // raw 32 bytes for Ed25519; or raw bytes for AnyPublicKey
    pub sig_scheme: u8,
    pub sig_bytes: Vec<u8>,        // raw 64 bytes for Ed25519
    pub full_message: String,
    // for AnyPublicKey: inner variant + inner key bytes (needed for auth key check)
    pub any_pk_inner_variant: Option<u8>,
    pub any_pk_inner_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RequestForDecryptionKey {
    pub contract_id_scheme: u8,
    pub aptos_contract_id: AptosContractId,
    pub domain: Vec<u8>,
    pub proof_scheme: u8,
    pub aptos_proof: AptosProofOfPermission,
}

impl RequestForDecryptionKey {
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim())?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut r = BcsReader::new(data);

        // ContractID
        let contract_id_scheme = r.read_u8()?;
        if contract_id_scheme != 0 {
            return Err(anyhow!("Only Aptos contract scheme supported, got {}", contract_id_scheme));
        }
        let aptos_contract_id = read_aptos_contract_id(&mut r)?;

        // domain
        let domain = r.read_bytes()?;

        // ProofOfPermission
        let proof_scheme = r.read_u8()?;
        if proof_scheme != 0 {
            return Err(anyhow!("Only Aptos proof scheme supported, got {}", proof_scheme));
        }
        let aptos_proof = read_aptos_proof(&mut r)?;

        Ok(RequestForDecryptionKey {
            contract_id_scheme,
            aptos_contract_id,
            domain,
            proof_scheme,
            aptos_proof,
        })
    }
}

fn read_aptos_contract_id(r: &mut BcsReader) -> Result<AptosContractId> {
    let chain_id = r.read_u8()?;
    let addr_bytes = r.read_fixed_bytes(32)?;
    let module_addr: [u8; 32] = addr_bytes.try_into().unwrap();
    let module_name = r.read_str()?;
    let function_name = r.read_str()?;
    Ok(AptosContractId { chain_id, module_addr, module_name, function_name })
}

fn read_aptos_proof(r: &mut BcsReader) -> Result<AptosProofOfPermission> {
    // userAddr: 32 fixed bytes
    let addr_bytes = r.read_fixed_bytes(32)?;
    let user_addr: [u8; 32] = addr_bytes.try_into().unwrap();

    // public key scheme
    let pk_scheme = r.read_u8()?;
    let (pubkey_bytes, any_pk_inner_variant, any_pk_inner_bytes) = match pk_scheme {
        0 => {
            // Ed25519: ULEB128(32) + 32 bytes
            let raw = r.read_bytes()?;
            if raw.len() != 32 {
                return Err(anyhow!("Ed25519 pubkey must be 32 bytes, got {}", raw.len()));
            }
            (raw, None, vec![])
        }
        1 => {
            // AnyPublicKey: ULEB128(inner_variant) + inner_key.serialize()
            let inner_variant = r.read_uleb128()? as u8;
            let inner_bytes = r.read_bytes()?; // ULEB128(len) + bytes
            // Build the full AnyPublicKey serialized bytes for auth key
            // = ULEB128(variant) + ULEB128(len) + inner_bytes
            let mut full = vec![inner_variant];
            // re-encode length prefix
            encode_uleb128(inner_bytes.len() as u64, &mut full);
            full.extend_from_slice(&inner_bytes);
            (inner_bytes.clone(), Some(inner_variant), full)
        }
        _ => return Err(anyhow!("Unsupported pk_scheme: {}", pk_scheme)),
    };

    // signature scheme
    let sig_scheme = r.read_u8()?;
    let sig_bytes = match sig_scheme {
        0 => {
            // Ed25519: ULEB128(64) + 64 bytes
            let raw = r.read_bytes()?;
            if raw.len() != 64 {
                return Err(anyhow!("Ed25519 sig must be 64 bytes, got {}", raw.len()));
            }
            raw
        }
        1 => {
            // AnySignature: ULEB128(inner_variant) + inner_sig.serialize()
            let _inner_variant = r.read_uleb128()?;
            r.read_bytes()? // the inner sig bytes
        }
        _ => return Err(anyhow!("Unsupported sig_scheme: {}", sig_scheme)),
    };

    let full_message = r.read_str()?;

    Ok(AptosProofOfPermission {
        user_addr,
        pk_scheme,
        pubkey_bytes,
        sig_scheme,
        sig_bytes,
        full_message,
        any_pk_inner_variant,
        any_pk_inner_bytes,
    })
}

fn encode_uleb128(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}
