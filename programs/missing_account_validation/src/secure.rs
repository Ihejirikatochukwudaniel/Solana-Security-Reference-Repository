use anchor_lang::prelude::*;
use anchor_spl::token::{self, Transfer, TokenAccount, Mint, Token};

// ============================================================================
// FIX: Proper Account Validation
// ============================================================================
//
// WHAT'S FIXED:
// This version properly validates all accounts before operating on them:
// - Uses Anchor's token constraints to ensure accounts belong to the correct mint
// - Properly structures token accounts with constraints
// - Validates signer authority
// - Uses safe token program CPI
//
// BEST PRACTICES:
// 1. Always specify account constraints in #[account(...)] macros
// 2. Use Anchor's SPL token helpers for token operations
// 3. Validate that mints match before transfers
// 4. Verify signer status for sensitive operations
//
// ============================================================================

declare_id!("11111111111111111111111111111111");

#[program]
pub mod missing_account_validation_secure {
    use super::*;

    /// SECURE: Transfers tokens with proper account validation
    pub fn transfer_tokens_safe(
        ctx: Context<TransferSafe>,
        amount: u64,
    ) -> Result<()> {
        // All account validation is done by Anchor via the #[account(...)] constraints
        // If we reach this point, we can be confident:
        // 1. token_from and token_to belong to the correct mint
        // 2. authority has signer status
        // 3. All accounts are properly initialized

        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.token_from.to_account_info(),
                    to: ctx.accounts.token_to.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?;

        msg!("Successfully transferred {} tokens", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferSafe<'info> {
    /// The mint defining which tokens we're working with
    pub mint: Account<'info, Mint>,

    /// Token account we're transferring FROM
    /// CONSTRAINT: Must belong to the specified mint
    /// CONSTRAINT: Must be mutable (we're updating balance)
    #[account(
        mut,
        associated_token_account::mint = mint,
    )]
    pub token_from: Account<'info, TokenAccount>,

    /// Token account we're transferring TO
    /// CONSTRAINT: Must belong to the same mint
    /// CONSTRAINT: Must be mutable
    #[account(
        mut,
        associated_token_account::mint = mint,
    )]
    pub token_to: Account<'info, TokenAccount>,

    /// The authority initiating the transfer
    /// CONSTRAINT: Must be a signer (Anchor verifies this)
    #[account(signer)]
    pub authority: Signer<'info>,

    /// The token program (standard Solana token program)
    pub token_program: Program<'info, Token>,
}
