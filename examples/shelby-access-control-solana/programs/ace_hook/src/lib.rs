// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! ACE Hook Program
//!
//! This program serves as the access control "hook" that ACE workers
//! call to verify if a user has permission to decrypt content.
//!
//! # Why a Separate Program?
//!
//! With a single program containing multiple instructions, there's no reliable
//! way for decryption workers to confirm that a proof-of-permission transaction
//! actually calls the access verification logic (and not some other instruction).
//!
//! By using a dedicated program with a single `assert_access` instruction,
//! workers can simply verify that the transaction's first instruction targets
//! this program's ID.
//!
//! # How It Works
//!
//! 1. User wants to decrypt content
//! 2. User builds a transaction calling `assert_access` with the blob identifier
//! 3. User signs the transaction (proving they control the account)
//! 4. User sends the signed transaction to ACE workers
//! 5. Workers verify the transaction targets this program
//! 6. Workers simulate the transaction - if `assert_access` succeeds, they release key shares
//!
//! # Access Verification
//!
//! The `assert_access` instruction verifies:
//! 1. The BlobMetadata PDA exists and is owned by access_control
//! 2. The Receipt PDA exists and is owned by access_control
//! 3. Both PDAs derive from the correct seeds (matching the blob name)
//! 4. The Receipt's seqnum matches the BlobMetadata's seqnum
//!
//! If all checks pass, the user has valid access to decrypt the content.

use anchor_lang::prelude::*;
use access_control::{BlobMetadata, Receipt, ID as ACCESS_CONTROL_PROGRAM_ID};

// Declare the program ID (must match Anchor.toml)
declare_id!("CUM2ENS7vKsMLvJ9Njsa1qmvwQwBC6ki1YPvrrcTYv8U");

#[program]
pub mod ace_hook {
    use super::*;

    /// Assert that the caller has access to the specified blob.
    ///
    /// This instruction is designed to be signed by users and presented to
    /// ACE workers as proof of permission. ACE workers will simulate
    /// this transaction to verify the user has valid access.
    ///
    /// # Arguments
    ///
    /// * `full_blob_name_bytes` - Full blob identifier in format:
    ///   `"0x" + owner_aptos_addr (32 bytes) + "/" + blob_name`
    ///
    /// # Verification Steps
    ///
    /// 1. Parse the full blob name to extract owner address and blob name
    /// 2. Verify blob_metadata account is owned by access_control program
    /// 3. Verify receipt account is owned by access_control program
    /// 4. Derive expected PDAs and verify they match the provided accounts
    /// 5. Deserialize and verify receipt.seqnum == blob_metadata.seqnum
    ///
    /// # Errors
    ///
    /// * `InvalidAccountOwner` - Account not owned by access_control
    /// * `InvalidBlobName` - Malformed blob name format
    /// * `AccessDenied` - Seqnum mismatch (receipt is stale)
    pub fn assert_access(ctx: Context<AssertAccess>, full_blob_name_bytes: Vec<u8>) -> Result<()> {
        // ====================================================================
        // Step 1: Verify Account Ownership
        // ====================================================================
        
        // Debug logging for troubleshooting
        msg!("blob_metadata.owner = {}", ctx.accounts.blob_metadata.owner);
        msg!("receipt.owner = {}", ctx.accounts.receipt.owner);
        msg!("expected = {}", ACCESS_CONTROL_PROGRAM_ID);
        
        // Verify blob_metadata account is owned by the access_control program
        // This prevents attackers from passing fake metadata accounts
        if *ctx.accounts.blob_metadata.owner != ACCESS_CONTROL_PROGRAM_ID {
            msg!("FAIL: blob_metadata owner mismatch");
            return Err(ErrorCode::InvalidAccountOwner.into());
        }
        
        // Verify receipt account is owned by the access_control program
        if *ctx.accounts.receipt.owner != ACCESS_CONTROL_PROGRAM_ID {
            msg!("FAIL: receipt owner mismatch");
            return Err(ErrorCode::InvalidAccountOwner.into());
        }
        
        // ====================================================================
        // Step 2: Parse Full Blob Name
        // ====================================================================
        
        // Full blob name format:
        // [0:2]   "0x" prefix
        // [2:34]  owner_aptos_addr (32 bytes)
        // [34]    "/" separator
        // [35:]   blob_name
        
        // Validate minimum length and format
        if full_blob_name_bytes.len() < 35 
            || &full_blob_name_bytes[0..2] != b"0x" 
            || full_blob_name_bytes[34] != b'/' 
        {
            return Err(ErrorCode::InvalidBlobName.into());
        }
        
        // Extract owner's Aptos address (32 bytes)
        let owner_aptos_addr: [u8; 32] = full_blob_name_bytes[2..34]
            .try_into()
            .map_err(|_| ErrorCode::InvalidBlobName)?;
        
        // Extract blob name (everything after the "/" separator)
        let blob_name = &full_blob_name_bytes[35..];
        
        // ====================================================================
        // Step 3: Verify PDA Derivation
        // ====================================================================
        
        // Derive expected blob_metadata PDA using access_control's seeds
        let (expected_blob_metadata_pda, _bump) = Pubkey::find_program_address(
            &[
                b"blob_metadata",
                owner_aptos_addr.as_ref(),
                blob_name,
            ],
            &ACCESS_CONTROL_PROGRAM_ID,
        );
        
        // Verify the provided blob_metadata matches the expected PDA
        if ctx.accounts.blob_metadata.key() != expected_blob_metadata_pda {
            return Err(ErrorCode::InvalidAccountOwner.into());
        }
        
        // Derive expected receipt PDA using access_control's seeds
        let (expected_receipt_pda, _bump) = Pubkey::find_program_address(
            &[
                b"access",
                owner_aptos_addr.as_ref(),
                blob_name,
                ctx.accounts.user.key().as_ref(),
            ],
            &ACCESS_CONTROL_PROGRAM_ID,
        );
        
        // Verify the provided receipt matches the expected PDA
        if ctx.accounts.receipt.key() != expected_receipt_pda {
            return Err(ErrorCode::InvalidAccountOwner.into());
        }
        
        // ====================================================================
        // Step 4: Deserialize and Verify Access
        // ====================================================================
        
        // Manually deserialize BlobMetadata (owned by another program)
        // Skip the 8-byte Anchor discriminator
        let blob_metadata_data = &ctx.accounts.blob_metadata.try_borrow_data()?;
        let mut blob_metadata_slice = &blob_metadata_data[8..];
        let blob_metadata = BlobMetadata::deserialize(&mut blob_metadata_slice)?;
        
        // Manually deserialize Receipt (owned by another program)
        let receipt_data = &ctx.accounts.receipt.try_borrow_data()?;
        let mut receipt_slice = &receipt_data[8..];
        let receipt = Receipt::deserialize(&mut receipt_slice)?;

        // Verify sequence numbers match
        // If the content owner re-encrypted their content, old receipts become invalid
        require!(
            blob_metadata.seqnum == receipt.seqnum,
            ErrorCode::AccessDenied
        );

        msg!("Access verified: seqnum = {}", receipt.seqnum);
        Ok(())
    }
}

// ============================================================================
// Account Validation
// ============================================================================

/// Accounts required for the `assert_access` instruction.
///
/// Note: We use `AccountInfo` instead of `Account<BlobMetadata>` because these
/// accounts are owned by a different program (access_control). We manually
/// verify ownership and deserialize in the handler.
#[derive(Accounts)]
pub struct AssertAccess<'info> {
    /// BlobMetadata PDA from access_control program.
    /// We verify ownership and deserialize manually in the handler.
    /// CHECK: Account ownership verified in handler
    pub blob_metadata: AccountInfo<'info>,
    
    /// Receipt PDA from access_control program.
    /// Proves the user has purchased access.
    /// CHECK: Account ownership verified in handler
    pub receipt: AccountInfo<'info>,
    
    /// The user requesting access.
    /// Must sign the transaction to prove they control this account.
    pub user: Signer<'info>,
}

// ============================================================================
// Error Codes
// ============================================================================

#[error_code]
pub enum ErrorCode {
    /// User does not have valid access to this blob.
    /// Either no receipt exists, or the receipt's seqnum doesn't match.
    #[msg("Access denied")]
    AccessDenied,
    
    /// The full blob name is malformed.
    /// Expected format: "0x" + 32-byte address + "/" + blob name
    #[msg("Invalid blob name format")]
    InvalidBlobName,
    
    /// An account is not owned by the expected program.
    /// Either blob_metadata or receipt is not owned by access_control.
    #[msg("Invalid account owner")]
    InvalidAccountOwner,
}
