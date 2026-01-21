use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// ============================================================================
// VULNERABILITY: Reentrancy Risk
// ============================================================================
//
// WHAT'S BROKEN:
// This program performs external calls (CPI) before updating its internal state.
// An attacker's program can call back into this program (reentrancy) before the
// state is updated, allowing them to drain funds or manipulate state.
//
// WHY IT'S UNSAFE:
// - Uses Interactions-Effects pattern (WRONG) instead of Checks-Effects-Interactions
// - External call happens before state update
// - Attacker can re-enter during the CPI call
// - Multiple withdrawals with same balance possible
//
// SEVERITY: CRITICAL
// ============================================================================

declare_id!("55555555555555555555555555555555");

#[program]
pub mod reentrancy_risk {
    use super::*;

    /// VULNERABLE: Withdraws tokens without updating state first
    pub fn withdraw_vulnerable(
        ctx: Context<WithdrawVulnerable>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_deposit;

        // VULNERABILITY: Pattern is Interactions-Effects (WRONG!)
        // We should do Checks-Effects-Interactions
        
        // CHECK: Verify user has enough balance
        require!(
            user.balance >= amount,
            CustomError::InsufficientBalance
        );

        // VULNERABILITY: INTERACTION comes BEFORE EFFECTS
        // We transfer tokens BEFORE updating the user's balance
        // During this CPI call, attacker can re-enter!
        
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.pool_token.to_account_info(),
                    to: ctx.accounts.user_token.to_account_info(),
                    authority: ctx.accounts.pool_signer.to_account_info(),
                },
            ),
            amount,
        )?;

        // VULNERABILITY: EFFECTS happen AFTER interaction
        // By this time, if attacker re-entered, this update is too late!
        // The reentering call saw the same balance and could withdraw again
        user.balance = user.balance.checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        pool.total_deposited = pool.total_deposited.checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        msg!("Withdrew {} tokens", amount);
        Ok(())
    }

    /// VULNERABLE: Initialize pool without reentrancy guards
    pub fn initialize_pool_vulnerable(
        ctx: Context<InitializePoolVulnerable>,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_deposited = 0;
        pool.total_available = 0;
        // NO reentrancy guard!

        msg!("Pool initialized");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub user_deposit: Account<'info, UserDeposit>,

    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,

    /// PDA that acts as authority for token account
    /// For this vulnerable example, it's not a true signer
    pub pool_signer: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct InitializePoolVulnerable<'info> {
    #[account(init, payer = authority, space = 8 + 8 + 8)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Pool {
    pub total_deposited: u64,
    pub total_available: u64,
    // VULNERABILITY: No reentrancy guard like a locked flag
}

#[account]
pub struct UserDeposit {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum CustomError {
    #[msg("Insufficient balance for withdrawal")]
    InsufficientBalance,

    #[msg("Arithmetic underflow")]
    ArithmeticUnderflow,

    #[msg("Pool is locked")]
    PoolLocked,
}
