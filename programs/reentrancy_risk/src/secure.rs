use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// ============================================================================
// FIX: Preventing Reentrancy
// ============================================================================
//
// WHAT'S FIXED:
// This version uses the Checks-Effects-Interactions (CEI) pattern:
// - Checks are performed first
// - State is updated BEFORE external calls
// - External interactions happen last
// - Reentrancy impossible because balance is already updated
//
// BEST PRACTICES:
// 1. Always follow Checks-Effects-Interactions pattern
// 2. Update state before making external calls
// 3. Use reentrancy guards (locked flags) if necessary
// 4. Mark state as "in-progress" before CPI
// 5. Understand Solana's call stack prevents self-reentrancy
//
// ============================================================================

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("55555555555555555555555555555555");

#[program]
pub mod reentrancy_risk_secure {
    use super::*;

    /// SECURE: Withdraw with Checks-Effects-Interactions pattern
    pub fn withdraw_safe(
        ctx: Context<WithdrawSafe>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_deposit;

        // SECURE: Pattern is Checks-Effects-Interactions (CORRECT!)

        // PHASE 1: CHECKS - Verify preconditions
        require!(
            user.balance >= amount,
            CustomError::InsufficientBalance
        );

        require!(
            pool.total_available >= amount,
            CustomError::InsufficientPoolFunds
        );

        // Additional security: Check pool is not locked (reentrancy guard)
        require!(
            !pool.locked,
            CustomError::PoolLocked
        );

        // PHASE 2: EFFECTS - Update state FIRST (before external calls)
        // Lock the pool to prevent reentrancy
        pool.locked = true;

        user.balance = user.balance.checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        pool.total_deposited = pool.total_deposited.checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        pool.total_available = pool.total_available.checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        // PHASE 3: INTERACTIONS - External calls happen LAST
        // By this point, the user's balance is already reduced
        // Even if attacker re-enters, they see the updated balance
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

        // Unlock the pool after successful transfer
        pool.locked = false;

        msg!("Safely withdrew {} tokens", amount);
        Ok(())
    }

    /// SECURE: Initialize pool with reentrancy guard
    pub fn initialize_pool_safe(
        ctx: Context<InitializePoolSafe>,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.total_deposited = 0;
        pool.total_available = 0;
        pool.locked = false; // SECURE: Initialize reentrancy guard

        msg!("Pool initialized with reentrancy protection");
        Ok(())
    }

    /// SECURE: Alternative - Deposit function with CEI pattern
    pub fn deposit_safe(
        ctx: Context<DepositSafe>,
        amount: u64,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let user = &mut ctx.accounts.user_deposit;

        // CHECKS
        require!(amount > 0, CustomError::InvalidAmount);
        require!(
            ctx.accounts.user_token.amount >= amount,
            CustomError::InsufficientBalance
        );

        // EFFECTS - Update state first
        user.balance = user.balance.checked_add(amount)
            .ok_or(CustomError::ArithmeticOverflow)?;

        pool.total_deposited = pool.total_deposited.checked_add(amount)
            .ok_or(CustomError::ArithmeticOverflow)?;

        pool.total_available = pool.total_available.checked_add(amount)
            .ok_or(CustomError::ArithmeticOverflow)?;

        // INTERACTIONS - Transfer user's tokens to pool
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_token.to_account_info(),
                    to: ctx.accounts.pool_token.to_account_info(),
                    authority: ctx.accounts.user_authority.to_account_info(),
                },
            ),
            amount,
        )?;

        msg!("Safely deposited {} tokens", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, PoolSafe>,

    #[account(mut)]
    pub user_deposit: Account<'info, UserDeposit>,

    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,

    /// PDA that acts as authority for token account
    pub pool_signer: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct InitializePoolSafe<'info> {
    #[account(init, payer = authority, space = 8 + 8 + 8 + 1)]
    pub pool: Account<'info, PoolSafe>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositSafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, PoolSafe>,

    #[account(mut)]
    pub user_deposit: Account<'info, UserDeposit>,

    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub pool_token: Account<'info, TokenAccount>,

    #[account(signer)]
    pub user_authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
}

#[account]
pub struct PoolSafe {
    pub total_deposited: u64,
    pub total_available: u64,
    pub locked: bool, // SECURE: Reentrancy guard
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

    #[msg("Insufficient pool funds")]
    InsufficientPoolFunds,

    #[msg("Arithmetic underflow")]
    ArithmeticUnderflow,

    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,

    #[msg("Pool is locked (reentrancy protection)")]
    PoolLocked,

    #[msg("Invalid amount")]
    InvalidAmount,
}
