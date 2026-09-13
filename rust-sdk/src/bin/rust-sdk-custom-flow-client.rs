// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Rust half of the custom-flow localnet scenario (`scenarios/test-rust-sdk-custom-flow.ts`),
//! the counterpart of `scenarios/python-sdk-custom-flow-client.py`: reads the fixture the TS
//! driver wrote, decrypts through the real worker HTTP endpoints with `decrypt_custom_flow`,
//! and exits 0 iff the plaintext matches.

use std::path::PathBuf;

use ace_sdk::aptos::ibe::{decrypt_custom_flow, CustomFlowArgs, Target};
use ace_sdk::aptos::AceDeployment;
use ace_sdk::wire::decode_hex;
use ace_sdk::AccountAddress;

#[derive(serde::Deserialize)]
struct Fixture {
    api_endpoint: String,
    contract_addr: String,
    keypair_id: String,
    chain_id: u8,
    module_addr: String,
    module_name: String,
    label_hex: String,
    payload_hex: String,
    enc_pk_hex: String,
    enc_sk_hex: String,
    ciphertext_hex: String,
    expected_plaintext: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: rust-sdk-custom-flow-client <fixture.json>");
        std::process::exit(2);
    }
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(e) = rt.block_on(run(PathBuf::from(&args[1]))) {
        eprintln!("rust custom-flow client failed: {e}");
        std::process::exit(1);
    }
}

async fn run(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let fx: Fixture = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let dep = AceDeployment::new(
        fx.api_endpoint,
        AccountAddress::from_str_relaxed(&fx.contract_addr)?,
    );
    let target = Target {
        ace_deployment: &dep,
        keypair_id: AccountAddress::from_str_relaxed(&fx.keypair_id)?,
        chain_id: fx.chain_id,
        module_addr: AccountAddress::from_str_relaxed(&fx.module_addr)?,
        module_name: &fx.module_name,
    };
    let plaintext = decrypt_custom_flow(
        CustomFlowArgs {
            target,
            label: &decode_hex(&fx.label_hex)?,
            enc_pk: &decode_hex(&fx.enc_pk_hex)?,
            enc_sk: &decode_hex(&fx.enc_sk_hex)?,
            payload: &decode_hex(&fx.payload_hex)?,
            tibe_scheme: None,
        },
        &decode_hex(&fx.ciphertext_hex)?,
    )
    .await?;
    if plaintext != fx.expected_plaintext.as_bytes() {
        return Err(format!(
            "plaintext mismatch: {:?} != {:?}",
            String::from_utf8_lossy(&plaintext),
            fx.expected_plaintext
        )
        .into());
    }
    println!(
        "rust-sdk custom-flow decrypt OK ({} bytes)",
        plaintext.len()
    );
    Ok(())
}
