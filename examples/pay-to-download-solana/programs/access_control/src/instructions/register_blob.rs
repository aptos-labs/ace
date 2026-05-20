// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Register Blob Instruction
//!
//! Lets content owners list a new ACE-gated blob for sale. Creates a
//! BlobMetadata PDA holding the price + a fresh sequence number. The
//! ciphertext is *not* stored on-chain — see the module docstring in
//! `lib.rs` for the off-chain delivery model.

use anchor_lang::prelude::*;
use crate::BlobMetadata;

// ============================================================================
// Accounts
// ============================================================================

/// Accounts required for registering a new blob.
#[derive(Accounts)]
#[instruction(owner_aptos_addr: [u8; 32], blob_name: String)]
pub struct RegisterBlob<'info> {
    /// BlobMetadata PDA to create.
    ///
    /// Seeds: ["blob_metadata", owner_aptos_addr, blob_name]
    ///
    /// Space allocation:
    /// - 8 bytes: Anchor discriminator
    /// - 32 bytes: owner (Pubkey)
    /// - 8 bytes: seqnum
    /// - 8 bytes: price
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 8 + 8,
        seeds = [b"blob_metadata", owner_aptos_addr.as_ref(), blob_name.as_bytes()],
        bump
    )]
    pub blob_metadata: Account<'info, BlobMetadata>,

    /// Content owner who pays for account creation.
    #[account(mut)]
    pub owner: Signer<'info>,

    /// System program for account creation.
    pub system_program: Program<'info, System>,
}

// ============================================================================
// Handler
// ============================================================================

/// Register a new ACE-gated blob listing for sale.
///
/// Creates a BlobMetadata PDA storing:
/// - The owner's Solana address
/// - The price to purchase access
/// - A sequence number (for invalidating old receipts)
///
/// The ciphertext itself is not stored on-chain. Alice keeps it and
/// delivers it to Bob via her chosen channel after purchase.
///
/// # Arguments
///
/// * `ctx` - Anchor context with accounts
/// * `owner_aptos_addr` - Owner's Aptos address (used in PDA seeds, not stored)
/// * `_blob_name` - Blob name (used in PDA seeds via instruction attribute)
/// * `price` - Price in lamports
#[allow(unused_variables)]
pub fn handler(
    ctx: Context<RegisterBlob>,
    owner_aptos_addr: [u8; 32],
    _blob_name: String,
    price: u64,
) -> Result<()> {
    let blob_metadata = &mut ctx.accounts.blob_metadata;

    // Set the owner to the signing Solana address
    blob_metadata.owner = ctx.accounts.owner.key();

    // Set the price for purchasing access
    blob_metadata.price = price;

    // Increment sequence number (starts at 1)
    // If content is re-registered, this invalidates old receipts
    blob_metadata.seqnum += 1;

    msg!("Blob registered: owner={}, price={}, seqnum={}",
         blob_metadata.owner,
         blob_metadata.price,
         blob_metadata.seqnum);

    Ok(())
}
