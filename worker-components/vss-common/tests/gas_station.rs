// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Manual integration test for the gas-station submission path.
//!
//! Submits `worker_config::register_pke_enc_key` on Aptos testnet using the gas
//! station so that the operator account pays no gas.
//!
//! Run with:
//!   ACE_TEST_ACCOUNT_ADDR=0x... \
//!   ACE_TEST_ACCOUNT_SK=0x...   \
//!   ACE_TEST_PKE_EK=0x...       \
//!   ACE_TEST_GAS_KEY=...        \
//!   cargo test -p vss-common --test gas_station -- --ignored --nocapture

use vss_common::{AptosRpc, TxnArg};

fn require_env(var: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| panic!("env var {var} is required"))
}

#[test]
#[ignore]
fn test_gas_station_register_pke_enc_key() {
    let rpc_url = std::env::var("ACE_TEST_RPC_URL")
        .unwrap_or_else(|_| "https://api.testnet.aptoslabs.com/v1".to_string());
    let rpc_apikey = std::env::var("ACE_TEST_RPC_APIKEY").ok();
    let gas_key = require_env("ACE_TEST_GAS_KEY");
    let account_addr = require_env("ACE_TEST_ACCOUNT_ADDR");
    let account_sk_hex = require_env("ACE_TEST_ACCOUNT_SK");
    let pke_ek_hex = require_env("ACE_TEST_PKE_EK");
    let contract_addr = std::env::var("ACE_TEST_CONTRACT_ADDR")
        .unwrap_or_else(|_| {
            "0xfe4cf5d9c85b474e698db59d20b4f035695c4d0df484a3c07b62909b97347103".to_string()
        });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let rpc = AptosRpc::new_with_gas_key(rpc_url, rpc_apikey, Some(gas_key));
        let sk = vss_common::parse_ed25519_signing_key_hex(&account_sk_hex)
            .expect("invalid account SK");
        let vk = sk.verifying_key();

        let ek_bytes = hex::decode(pke_ek_hex.trim_start_matches("0x"))
            .expect("invalid pke_ek hex");

        eprintln!("submitting register_pke_enc_key via gas station...");
        let hash = rpc
            .submit_txn(
                &sk,
                &vk,
                &account_addr,
                &format!("{}::worker_config::register_pke_enc_key", contract_addr),
                &[],
                &[TxnArg::Bytes(&ek_bytes)],
            )
            .await
            .expect("submit_txn failed");

        eprintln!("success: {hash}");
    });
}
