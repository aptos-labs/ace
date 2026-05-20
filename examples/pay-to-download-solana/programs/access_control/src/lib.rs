// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Pay-to-Download Access Control - Main Program
//!
//! This program manages ACE-encrypted content metadata and purchase receipts.
//! It's the "business logic" program that handles:
//! - Registering ACE-encrypted content with pricing
//! - Processing purchases and creating access receipts
//!
//! The actual access verification is done by the separate `ace_hook` program,
//! which reads the PDAs created by this program.
//!
//! # Encryption Model
//!
//! Content is encrypted directly with ACE — the ciphertext bytes stored in
//! the on-chain `BlobMetadata` PDA *are* the protected payload. There is no
//! intermediate symmetric-key wrapping layer. With ACE's current default
//! t-IBE scheme, direct encryption of reasonably-sized payloads is the
//! recommended pattern.
//!
//! # Account Structure
//!
//! ```text
//! BlobMetadata (PDA)
//! ├── owner: Pubkey            - Content owner's Solana address
//! ├── ciphertext_scheme: u8    - ACE ciphertext scheme version
//! ├── ciphertext: Vec<u8>      - ACE-encrypted content payload
//! ├── seqnum: u64              - Sequence number (increments on updates)
//! └── price: u64               - Price in lamports
//!
//! Receipt (PDA)
//! └── seqnum: u64              - Sequence number at time of purchase
//! ```
//!
//! # PDA Seeds
//!
//! - BlobMetadata: `["blob_metadata", owner_aptos_addr, blob_name]`
//! - Receipt: `["access", owner_aptos_addr, blob_name, buyer_pubkey]`

use anchor_lang::prelude::*;

// Declare the program ID (must match Anchor.toml)
declare_id!("Csx54S8XVLHgY5KW3peJiMaeYUgTirDoTAAGjqcjq1wu");

pub mod utils;
pub mod instructions;
pub use instructions::*;

// ============================================================================
// Account Structures
// ============================================================================

/// Metadata for a registered ACE-encrypted blob.
///
/// `ciphertext` is the ACE-encrypted content — it can only be decrypted by
/// users who pass the access check (i.e., hold a matching Receipt PDA).
#[account]
pub struct BlobMetadata {
    /// Solana address of the content owner
    pub owner: Pubkey,

    /// ACE ciphertext scheme version (for forward compatibility)
    pub ciphertext_scheme: u8,

    /// The ACE-encrypted content payload
    pub ciphertext: Vec<u8>,

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

    /// Register a new ACE-encrypted blob for sale.
    ///
    /// Creates a BlobMetadata PDA storing the ciphertext and price.
    /// The owner can later update the price or re-encrypt the content.
    ///
    /// # Arguments
    ///
    /// * `owner_aptos_addr` - Owner's Aptos address (32 bytes, used in PDA seeds)
    /// * `blob_name` - Name/identifier for the blob (used in PDA seeds)
    /// * `ciphertext_scheme` - ACE ciphertext scheme version
    /// * `ciphertext` - The ACE-encrypted content payload
    /// * `price` - Price in lamports to purchase access
    pub fn register_blob(
        ctx: Context<RegisterBlob>,
        owner_aptos_addr: [u8; 32],
        blob_name: String,
        ciphertext_scheme: u8,
        ciphertext: Vec<u8>,
        price: u64,
    ) -> Result<()> {
        instructions::register_blob::handler(ctx, owner_aptos_addr, blob_name, ciphertext_scheme, ciphertext, price)
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
