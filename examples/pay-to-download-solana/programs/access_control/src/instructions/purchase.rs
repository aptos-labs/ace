// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Purchase Instruction
//!
//! This instruction allows users to purchase access to an encrypted blob.
//! It transfers SOL from the buyer to the content owner and creates a
//! Receipt PDA proving the purchase.

use anchor_lang::prelude::*;
use crate::{BlobMetadata, Receipt};
use crate::utils::solana_addr_to_aptos_addr;

// ============================================================================
// Accounts
// ============================================================================

/// Accounts required for purchasing access to a blob.
#[derive(Accounts)]
#[instruction(owner_aptos_addr: [u8; 32], blob_name: String)]
pub struct Purchase<'info> {
    /// BlobMetadata PDA containing price and seqnum.
    /// Must already exist (created by register_blob).
    #[account(
        seeds = [b"blob_metadata", owner_aptos_addr.as_ref(), blob_name.as_bytes()],
        bump
    )]
    pub blob_metadata: Account<'info, BlobMetadata>,
    
    /// Receipt PDA to create.
    ///
    /// Seeds: ["access", owner_aptos_addr, blob_name, buyer_pubkey]
    ///
    /// This proves the buyer has purchased access at this seqnum.
    #[account(
        init,
        payer = buyer,
        space = 8 + 32 + 32 + 4 + 100, // discriminator + padding for future fields
        seeds = [b"access", owner_aptos_addr.as_ref(), blob_name.as_bytes(), buyer.key().as_ref()],
        bump
    )]
    pub receipt: Account<'info, Receipt>,
    
    /// The buyer purchasing access.
    /// SOL will be transferred from this account.
    #[account(mut)]
    pub buyer: Signer<'info>,
    
    /// Content owner receiving payment.
    /// This must be the same address stored in BlobMetadata.
    /// CHECK: We verify this matches the derived Aptos address
    #[account(mut)]
    pub owner: AccountInfo<'info>,
    
    /// System program for SOL transfer.
    pub system_program: Program<'info, System>,
}

// ============================================================================
// Handler
// ============================================================================

/// Purchase access to an encrypted blob.
///
/// This function:
/// 1. Verifies the owner's Solana address matches the provided Aptos address
/// 2. Transfers the price in SOL from buyer to owner
/// 3. Creates a Receipt PDA storing the current seqnum
///
/// # Arguments
///
/// * `ctx` - Anchor context with accounts
/// * `owner_aptos_addr` - Owner's Aptos address (for verification)
/// * `_blob_name` - Blob name (used in PDA seeds via instruction attribute)
///
/// # Errors
///
/// * `OwnerAddressMismatch` - The provided owner doesn't derive to the expected Aptos address
pub fn handler(ctx: Context<Purchase>, owner_aptos_addr: [u8; 32], _blob_name: String) -> Result<()> {
    let blob_metadata = &ctx.accounts.blob_metadata;
    
    // ========================================================================
    // Step 1: Verify Owner Address
    // ========================================================================
    
    // Derive the Aptos address from the provided Solana owner address
    // This ensures the payment goes to the legitimate content owner
    let derived_aptos_addr = solana_addr_to_aptos_addr(ctx.accounts.owner.key);
    require!(
        derived_aptos_addr.as_slice() == owner_aptos_addr,
        PurchaseError::OwnerAddressMismatch
    );
    
    // ========================================================================
    // Step 2: Transfer Payment
    // ========================================================================
    
    // Transfer SOL from buyer to owner using the system program
    anchor_lang::solana_program::program::invoke(
        &anchor_lang::solana_program::system_instruction::transfer(
            ctx.accounts.buyer.key,
            &ctx.accounts.owner.key(),
            blob_metadata.price,
        ),
        &[
            ctx.accounts.buyer.to_account_info(),
            ctx.accounts.owner.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
    )?;
    
    msg!("Payment transferred: {} lamports from {} to {}", 
         blob_metadata.price,
         ctx.accounts.buyer.key(),
         ctx.accounts.owner.key());

    // ========================================================================
    // Step 3: Create Receipt
    // ========================================================================
    
    // Store the current seqnum in the receipt
    // This proves the buyer purchased when the content had this seqnum
    // If the owner re-encrypts (incrementing seqnum), old receipts become invalid
    let receipt = &mut ctx.accounts.receipt;
    receipt.seqnum = blob_metadata.seqnum;
    
    msg!("Receipt created: buyer={}, seqnum={}", 
         ctx.accounts.buyer.key(),
         receipt.seqnum);

    Ok(())
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum PurchaseError {
    /// The provided owner Solana address doesn't derive to the expected Aptos address.
    /// This could indicate an attack or misconfiguration.
    #[msg("Owner Solana address does not derive to the provided Aptos address")]
    OwnerAddressMismatch,
}
