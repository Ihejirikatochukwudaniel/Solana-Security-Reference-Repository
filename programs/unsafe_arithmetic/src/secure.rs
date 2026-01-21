use anchor_lang::prelude::*;

// ============================================================================
// FIX: Safe Arithmetic Operations
// ============================================================================
//
// WHAT'S FIXED:
// This version implements checked arithmetic with overflow protection:
// - Uses checked_add/checked_sub that return Option
// - Validates results before using them
// - Fails safely on arithmetic errors
//
// BEST PRACTICES:
// 1. Always use checked arithmetic (checked_add, checked_sub, checked_mul)
// 2. Use require! to validate arithmetic results
// 3. Consider using i128 for intermediate calculations
// 4. Document assumptions about range of values
//
// ============================================================================

use anchor_lang::prelude::*;

declare_id!("33333333333333333333333333333333");

#[program]
pub mod unsafe_arithmetic_secure {
    use super::*;

    /// SECURE: Deposit with checked arithmetic
    pub fn deposit_safe(
        ctx: Context<DepositSafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // SECURE: Use checked_add which returns Option
        // This prevents silent wrapping on overflow
        account.total_deposited = account
            .total_deposited
            .checked_add(amount)
            .ok_or(CustomError::ArithmeticOverflow)?;

        // SECURE: Checked multiplication for reward calculation
        let reward_rate = 100u64;
        let rewards = amount
            .checked_mul(reward_rate)
            .ok_or(CustomError::ArithmeticOverflow)?;
        
        account.total_rewards = account
            .total_rewards
            .checked_add(rewards)
            .ok_or(CustomError::ArithmeticOverflow)?;

        msg!("Deposited: {}, Total: {}", amount, account.total_deposited);
        Ok(())
    }

    /// SECURE: Withdrawal with checked arithmetic
    pub fn withdraw_safe(
        ctx: Context<WithdrawSafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // SECURE: Use checked_sub to prevent underflow
        account.total_available = account
            .total_available
            .checked_sub(amount)
            .ok_or(CustomError::ArithmeticUnderflow)?;

        msg!("Withdrew: {}, Remaining: {}", amount, account.total_available);
        Ok(())
    }

    /// SECURE: Mint tokens with overflow protection
    pub fn mint_interest_safe(
        ctx: Context<MintInterestSafe>,
        base_amount: u64,
        interest_rate: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // Validate inputs first
        require!(interest_rate <= 10000, CustomError::InvalidInterestRate); // max 100%

        // SECURE: Use checked_mul to detect overflow early
        let interest = base_amount
            .checked_mul(interest_rate)
            .ok_or(CustomError::ArithmeticOverflow)?
            .checked_div(100)
            .ok_or(CustomError::ArithmeticOverflow)?;
        
        account.total_minted = account
            .total_minted
            .checked_add(interest)
            .ok_or(CustomError::ArithmeticOverflow)?;

        msg!("Minted interest: {}", interest);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DepositSafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct MintInterestSafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[account]
pub struct Pool {
    pub total_deposited: u64,
    pub total_available: u64,
    pub total_rewards: u64,
    pub total_minted: u64,
}

#[error_code]
pub enum CustomError {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    
    #[msg("Arithmetic underflow detected")]
    ArithmeticUnderflow,
    
    #[msg("Invalid interest rate")]
    InvalidInterestRate,
}
