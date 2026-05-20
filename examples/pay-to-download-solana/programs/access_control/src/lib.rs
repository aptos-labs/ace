// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Pay-to-Download Access Control - Main Program
//!
//! This program manages on-chain *listing metadata* + purchase receipts for
//! ACE-encrypted content. It does NOT store the ciphertext itself — content
//! is encrypted by Alice (off-chain) and delivered to Bob via whatever
//! channel the application chooses (CDN, IPFS, direct upload after purchase,
//! etc.). The chain only records what's for sale, at what price, and who
//! has paid; the access-verification logic (`ace_hook::assert_access`) only
//! needs `BlobMetadata.seqnum` to validate that a Receipt is still current.
//!
//! # Encryption Model
//!
//! Content is encrypted directly with ACE — no intermediate symmetric-key
//! wrapping layer. With ACE's current default t-IBE scheme, direct
//! encryption of reasonably-sized payloads is the recommended pattern.
//!
//! # Account Structure
//!
//! ```text
//! BlobMetadata (PDA)
//! ├── owner: Pubkey            - Content owner's Solana address
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

/// On-chain listing metadata for an ACE-gated blob. The ciphertext itself
/// lives off-chain (delivered by the seller via storage / CDN / direct
/// transfer). This account only records what's for sale and at what price.
#[account]
pub struct BlobMetadata {
    /// Solana address of the content owner
    pub owner: Pubkey,

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

    /// Register a new ACE-gated blob listing for sale.
    ///
    /// Creates a BlobMetadata PDA storing the price + a fresh sequence
    /// number. The ciphertext itself is not on-chain — Alice keeps it and
    /// delivers it to Bob via her chosen channel after purchase.
    ///
    /// # Arguments
    ///
    /// * `owner_aptos_addr` - Owner's Aptos address (32 bytes, used in PDA seeds)
    /// * `blob_name` - Name/identifier for the blob (used in PDA seeds)
    /// * `price` - Price in lamports to purchase access
    pub fn register_blob(
        ctx: Context<RegisterBlob>,
        owner_aptos_addr: [u8; 32],
        blob_name: String,
        price: u64,
    ) -> Result<()> {
        instructions::register_blob::handler(ctx, owner_aptos_addr, blob_name, price)
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
