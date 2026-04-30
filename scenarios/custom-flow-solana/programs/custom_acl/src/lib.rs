// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Custom ACL Program
//!
//! This program demonstrates the ACE custom-flow hook interface on Solana.
//!
//! The admin stores an access code for each label. The `assert_custom_acl`
//! instruction decodes the ACE `CustomFullRequestBytes` from its argument,
//! derives the expected CodeEntry PDA from the embedded label, and asserts
//! that the embedded payload equals the stored code.
//!
//! In production the payload would be a zero-knowledge proof; here a plain
//! byte comparison stands in as an illustrative substitute.
//!
//! # Instructions
//!
//! - `register_code(label, code)` — admin stores access code for `label`.
//! - `assert_custom_acl(full_request_bytes)` — ACE workers simulate this to
//!   verify the payload matches the stored code before releasing key shares.

use ace_sdk::decode_custom_request;
use anchor_lang::prelude::*;

declare_id!("Bqt7ixcRELKJuQhpvajTM5WbwbzgPA7Ee9zYiiz8tXJX");

#[program]
pub mod custom_acl {
    use super::*;

    /// Store `code` as the required proof for `label`.
    pub fn register_code(ctx: Context<RegisterCode>, label: Vec<u8>, code: Vec<u8>) -> Result<()> {
        let entry = &mut ctx.accounts.code_entry;
        entry.code = code;
        entry.bump = ctx.bumps.code_entry;
        Ok(())
    }

    /// ACE hook: verify that the payload in `full_request_bytes` matches the
    /// stored code for the embedded label.
    ///
    /// ACE workers simulate this instruction to determine whether to release
    /// a decryption key share. If it succeeds the payload is accepted; if it
    /// aborts the worker withholds the share.
    pub fn assert_custom_acl(
        ctx: Context<AssertCustomAcl>,
        full_request_bytes: Vec<u8>,
    ) -> Result<()> {
        let decoded = decode_custom_request(&full_request_bytes)
            .map_err(|_| ErrorCode::InvalidRequestBytes)?;

        // Verify code_entry PDA derives from the label inside the request.
        let (expected_pda, _bump) = Pubkey::find_program_address(
            &[b"code", decoded.label.as_ref()],
            &crate::ID,
        );
        require!(
            ctx.accounts.code_entry.key() == expected_pda,
            ErrorCode::InvalidCodeEntry
        );
        require!(
            ctx.accounts.code_entry.owner == &crate::ID,
            ErrorCode::InvalidCodeEntry
        );

        // Deserialize CodeEntry; skip the 8-byte Anchor discriminator.
        let data = ctx.accounts.code_entry.try_borrow_data()?;
        let mut slice = &data[8..];
        let code_entry =
            CodeEntry::deserialize(&mut slice).map_err(|_| ErrorCode::InvalidCodeEntry)?;

        require!(decoded.payload == code_entry.code, ErrorCode::AccessDenied);
        Ok(())
    }
}

// ── Account structs ───────────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(label: Vec<u8>)]
pub struct RegisterCode<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 4 + 64 + 1,
        seeds = [b"code", label.as_slice()],
        bump,
    )]
    pub code_entry: Account<'info, CodeEntry>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AssertCustomAcl<'info> {
    /// CodeEntry PDA for the label embedded in full_request_bytes.
    /// Ownership and derivation are verified in the handler.
    /// CHECK: verified in handler
    pub code_entry: AccountInfo<'info>,
}

#[account]
pub struct CodeEntry {
    pub code: Vec<u8>,
    pub bump: u8,
}

// ── Error codes ───────────────────────────────────────────────────────────────

#[error_code]
pub enum ErrorCode {
    #[msg("Access denied: payload does not match stored code")]
    AccessDenied,
    #[msg("Failed to decode full_request_bytes")]
    InvalidRequestBytes,
    #[msg("code_entry does not derive from the expected label")]
    InvalidCodeEntry,
}
