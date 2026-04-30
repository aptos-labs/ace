// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Utility Functions
//!
//! This module provides utility functions for cross-chain address derivation.
//!
//! # Solana → Aptos Address Derivation
//!
//! Solana addresses are converted to Aptos Derivable Abstracted Account (DAA)
//! addresses to enable cross-chain identity. This allows Solana users to have
//! a corresponding Aptos identity without needing an actual Aptos account.
//!
//! The derivation uses:
//! - Authentication function: `0x1::solana_derivable_account::authenticate`
//! - Domain: `explorer.shelby.xyz`
//!
//! ```text
//! Solana PublicKey → Hash(auth_function_info + account_identifier) → Aptos Address
//!
//! Where:
//! - auth_function_info = 0x1::solana_derivable_account::authenticate
//! - account_identifier = BCS(solana_base58_address) + BCS(domain)
//! ```

use anchor_lang::prelude::Pubkey;
use sha3::{Digest, Sha3_256};

/// Domain identifier for the application.
/// Used as part of the account identifier when deriving Aptos addresses.
const DOMAIN: &str = "explorer.shelby.xyz";

/// Domain separator byte appended to the hash.
/// This is part of the Aptos address derivation specification.
const ADDRESS_DOMAIN_SEPARATOR: u8 = 5;

/// Module address 0x1 as 32 bytes (left-padded with zeros).
/// This is where the `solana_derivable_account` module lives.
const MODULE_ADDRESS: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

/// Convert a Solana address to an Aptos Derivable Abstracted Account (DAA) address.
///
/// This function computes the Aptos address by hashing:
/// 1. The authentication function info (module address + module name + function name)
/// 2. The account identifier (Solana base58 address + domain)
/// 3. A domain separator byte
///
/// This matches the TypeScript implementation in `@aptos-labs/ts-sdk`:
/// `DerivableAbstractedAccount.computeAccountAddress`
///
/// # Arguments
///
/// * `solana_addr` - The Solana public key to convert
///
/// # Returns
///
/// A 32-byte vector representing the Aptos address
///
/// # Example
///
/// ```ignore
/// let solana_addr: Pubkey = "F9E3oTFhkvY5WdjsV33E1pb3FyBe7PHwpT9TVtG7tei7".parse().unwrap();
/// let aptos_addr = solana_addr_to_aptos_addr(&solana_addr);
/// // aptos_addr = 0x9ee58f972ab7e54dfe650b1150cfff406ac6d7de25392540ef4046ca19a5aaab
/// ```
pub fn solana_addr_to_aptos_addr(solana_addr: &Pubkey) -> Vec<u8> {
    // Function info components
    let module_name = "solana_derivable_account";
    let function_name = "authenticate";

    let mut hasher = Sha3_256::new();

    // ========================================================================
    // Part 1: Serialize Function Info
    // ========================================================================
    
    // 1. AccountAddress (32 bytes, fixed size - no length prefix)
    hasher.update(MODULE_ADDRESS);
    
    // 2. Module name (BCS string: ULEB128 length + UTF-8 bytes)
    hasher.update(&bcs_serialize_str(module_name));
    
    // 3. Function name (BCS string: ULEB128 length + UTF-8 bytes)
    hasher.update(&bcs_serialize_str(function_name));

    // ========================================================================
    // Part 2: Build Account Identifier
    // ========================================================================
    
    // Account identifier = BCS(solana_base58) || BCS(domain)
    let solana_base58 = solana_addr.to_string();
    let mut account_identifier = bcs_serialize_str(&solana_base58);
    account_identifier.extend(bcs_serialize_str(DOMAIN));

    // Serialize account identifier as bytes (ULEB128 length + raw bytes)
    hasher.update(&bcs_serialize_bytes(&account_identifier));

    // ========================================================================
    // Part 3: Append Domain Separator
    // ========================================================================
    
    hasher.update([ADDRESS_DOMAIN_SEPARATOR]);

    hasher.finalize().to_vec()
}

/// BCS-serialize a string: ULEB128 length followed by UTF-8 bytes.
///
/// # Arguments
///
/// * `s` - The string to serialize
fn bcs_serialize_str(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = uleb128_encode(bytes.len());
    result.extend(bytes);
    result
}

/// BCS-serialize bytes: ULEB128 length followed by raw bytes.
///
/// # Arguments
///
/// * `b` - The bytes to serialize
fn bcs_serialize_bytes(b: &[u8]) -> Vec<u8> {
    let mut result = uleb128_encode(b.len());
    result.extend(b);
    result
}

/// Encode a usize as ULEB128 (Unsigned Little Endian Base 128).
///
/// ULEB128 is a variable-length encoding where:
/// - Each byte uses 7 bits for data and 1 bit to indicate continuation
/// - The high bit (0x80) is set if more bytes follow
///
/// # Arguments
///
/// * `value` - The value to encode
fn uleb128_encode(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        // Take the low 7 bits
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        
        // Set continuation bit if more bytes needed
        if value != 0 {
            byte |= 0x80;
        }
        
        result.push(byte);
        
        if value == 0 {
            break;
        }
    }
    result
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that Solana→Aptos address derivation matches the TypeScript implementation.
    /// This test case is shared between TypeScript (e2e.ts) and Rust.
    #[test]
    fn test_solana_addr_to_aptos_addr() {
        let solana_addr: Pubkey = "F9E3oTFhkvY5WdjsV33E1pb3FyBe7PHwpT9TVtG7tei7"
            .parse()
            .unwrap();
        let aptos_addr = solana_addr_to_aptos_addr(&solana_addr);

        let expected = hex_to_vec("9ee58f972ab7e54dfe650b1150cfff406ac6d7de25392540ef4046ca19a5aaab");
        assert_eq!(aptos_addr, expected);
    }

    /// Helper function to convert hex string to byte vector.
    fn hex_to_vec(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
