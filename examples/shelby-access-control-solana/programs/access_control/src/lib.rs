// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shelby Access Control - Main Program
//!
//! This program manages encrypted blob metadata and purchase receipts.
//! It's the "business logic" program that handles:
//! - Registering encrypted content (GreenBox) with pricing
//! - Processing purchases and creating access receipts
//!
//! The actual access verification is done by the separate `ace_hook` program,
//! which reads the PDAs created by this program.
//!
//! # Account Structure
//!
//! ```text
//! BlobMetadata (PDA)
//! ├── owner: Pubkey           - Content owner's Solana address
//! ├── green_box_scheme: u8    - Encryption scheme version
//! ├── green_box_bytes: Vec<u8> - Encrypted symmetric key (GreenBox)
//! ├── seqnum: u64             - Sequence number (increments on updates)
//! └── price: u64              - Price in lamports
//!
//! Receipt (PDA)
//! └── seqnum: u64             - Sequence number at time of purchase
//! ```
//!
//! # PDA Seeds
//!
//! - BlobMetadata: `["blob_metadata", owner_aptos_addr, blob_name]`
//! - Receipt: `["access", owner_aptos_addr, blob_name, buyer_pubkey]`

use anchor_lang::prelude::*;

// Declare the program ID (must match Anchor.toml)
declare_id!("WhBoxsYfAhJNRRjXGUF7iUEXmBSnPiY72k86AkMSkro");

pub mod utils;
pub mod instructions;
pub use instructions::*;

// ============================================================================
// Account Structures
// ============================================================================

/// Metadata for a registered encrypted blob.
///
/// This account stores information about an encrypted file that is available
/// for purchase. The `green_box_bytes` contains the encrypted symmetric key
/// (GreenBox) that can only be decrypted by users with valid access.
#[account]
pub struct BlobMetadata {
    /// Solana address of the content owner
    pub owner: Pubkey,
    
    /// Encryption scheme version (for forward compatibility)
    pub green_box_scheme: u8,
    
    /// The encrypted symmetric key (GreenBox)
    /// This is the ACE-encrypted version of the RedKey
    pub green_box_bytes: Vec<u8>,
    
    /// Sequence number, incremented on each update
    /// Used to invalidate old receipts if the content is re-encrypted
    pub seqnum: u64,
    
    /// Price in lamports to purchase access
    pub price: u64,
}

/// Receipt proving a user has purchased access to a blob.
///
/// When a user purchases access, a Receipt PDA is created.
/// The `seqnum` must match the BlobMetadata's `seqnum` for access to be valid.
/// This allows content owners to invalidate access by updating their content.
#[account]
pub struct Receipt {
    /// Sequence number at time of purchase
    /// Must match BlobMetadata.seqnum for access to be granted
    pub seqnum: u64,
}

// ============================================================================
// Program Instructions
// ============================================================================

#[program]
pub mod access_control {
    use super::*;

    /// Register a new encrypted blob for sale.
    ///
    /// Creates a BlobMetadata PDA storing the encrypted key and price.
    /// The owner can later update the price or re-encrypt the content.
    ///
    /// # Arguments
    ///
    /// * `owner_aptos_addr` - Owner's Aptos address (32 bytes, used in PDA seeds)
    /// * `blob_name` - Name/identifier for the blob (used in PDA seeds)
    /// * `green_box_scheme` - Encryption scheme version
    /// * `green_box_bytes` - The encrypted symmetric key (GreenBox)
    /// * `price` - Price in lamports to purchase access
    pub fn register_blob(
        ctx: Context<RegisterBlob>,
        owner_aptos_addr: [u8; 32],
        blob_name: String,
        green_box_scheme: u8,
        green_box_bytes: Vec<u8>,
        price: u64,
    ) -> Result<()> {
        instructions::register_blob::handler(ctx, owner_aptos_addr, blob_name, green_box_scheme, green_box_bytes, price)
    }

    /// Purchase access to an encrypted blob.
    ///
    /// Transfers SOL from the buyer to the content owner and creates a
    /// Receipt PDA proving the purchase. The Receipt's seqnum is set to
    /// the current BlobMetadata.seqnum.
    ///
    /// # Arguments
    ///
    /// * `owner_aptos_addr` - Owner's Aptos address (for PDA derivation)
    /// * `blob_name` - Name of the blob to purchase access to
    pub fn purchase(ctx: Context<Purchase>, owner_aptos_addr: [u8; 32], blob_name: String) -> Result<()> {
        instructions::purchase::handler(ctx, owner_aptos_addr, blob_name)
    }
}
