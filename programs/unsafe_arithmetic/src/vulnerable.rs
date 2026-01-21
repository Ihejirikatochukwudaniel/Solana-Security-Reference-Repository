use anchor_lang::prelude::*;

// ============================================================================
// VULNERABILITY: Unsafe Arithmetic
// ============================================================================
//
// WHAT'S BROKEN:
// This program performs arithmetic operations without overflow/underflow
// protection. Attackers can exploit wrapping arithmetic to manipulate
// token balances, causing unexpected state corruption or fund loss.
//
// WHY IT'S UNSAFE:
// - Using unchecked arithmetic operations
// - Wrapping behavior silently corrupts state
// - No validation of results before using them
// - Integer overflows become silent bugs
//
// SEVERITY: HIGH
// ============================================================================

declare_id!("33333333333333333333333333333333");

#[program]
pub mod unsafe_arithmetic {
    use super::*;

    /// VULNERABLE: Deposit with unchecked arithmetic
    pub fn deposit_unsafe(
        ctx: Context<DepositUnsafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // VULNERABILITY: Using wrapping add without overflow checks
        // If pool.total_deposited is u64::MAX and someone deposits 1,
        // it wraps to 0 instead of overflowing!
        account.total_deposited = account.total_deposited.wrapping_add(amount);

        // VULNERABILITY: Using unchecked multiplication
        // If we calculate rewards without checking overflow:
        let reward_rate = 100u64; // 100 basis points
        let rewards = amount.wrapping_mul(reward_rate); // Could overflow!
        account.total_rewards = account.total_rewards.wrapping_add(rewards);

        msg!("Deposited: {}, Total: {}", amount, account.total_deposited);
        Ok(())
    }

    /// VULNERABLE: Withdrawal with potential underflow
    pub fn withdraw_unsafe(
        ctx: Context<WithdrawUnsafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // VULNERABILITY: No overflow check on the subtraction
        // If amount > total_available, this wraps instead of failing
        account.total_available = account.total_available.wrapping_sub(amount);

        msg!("Withdrew: {}, Remaining: {}", amount, account.total_available);
        Ok(())
    }

    /// VULNERABLE: Mint new tokens with unsafe calculation
    pub fn mint_interest_unsafe(
        ctx: Context<MintInterestUnsafe>,
        base_amount: u64,
        interest_rate: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.pool;

        // VULNERABILITY: Multiplication without overflow check
        // If base_amount = u64::MAX/2 and interest_rate = 3, overflow!
        let interest = base_amount.wrapping_mul(interest_rate) / 100;
        
        account.total_minted = account.total_minted.wrapping_add(interest);

        msg!("Minted interest: {}", interest);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct DepositUnsafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct WithdrawUnsafe<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct MintInterestUnsafe<'info> {
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
}
