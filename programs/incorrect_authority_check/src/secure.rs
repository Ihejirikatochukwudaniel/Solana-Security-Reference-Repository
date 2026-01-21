use anchor_lang::prelude::*;

// ============================================================================
// FIX: Proper Authority Checks
// ============================================================================
//
// WHAT'S FIXED:
// This version implements proper authority verification:
// - Authority is marked as a signer (prevents unauthorized claims)
// - Explicit validation that authority matches the stored owner
// - Multiple layers of validation for sensitive operations
//
// BEST PRACTICES:
// 1. Always mark authorities as #[account(signer)]
// 2. Explicitly compare authority.key() == stored_owner
// 3. Use constraints to codify permission rules
// 4. Fail fast if authority is wrong (require! macro)
//
// ============================================================================

use anchor_lang::prelude::*;

declare_id!("22222222222222222222222222222222");

#[program]
pub mod incorrect_authority_check_secure {
    use super::*;

    /// SECURE: Initialize account with proper authority setup
    pub fn initialize_safe(
        ctx: Context<InitializeSafe>,
        initial_amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.user_account;
        
        // Only the signer (authority) can initialize their own account
        // This is enforced by Anchor via the #[account(signer)] constraint
        
        account.owner = ctx.accounts.authority.key();
        account.balance = initial_amount;

        msg!("Account initialized with owner: {}", account.owner);
        Ok(())
    }

    /// SECURE: Withdraw with explicit authority validation
    pub fn withdraw_safe(
        ctx: Context<WithdrawSafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.user_account;

        // EXPLICIT VALIDATION: Verify the signer IS the owner
        require_eq!(
            ctx.accounts.authority.key(),
            account.owner,
            CustomError::Unauthorized
        );

        require!(account.balance >= amount, CustomError::InsufficientFunds);
        
        account.balance -= amount;
        
        msg!("Withdrew {} SOL", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeSafe<'info> {
    /// The user account to initialize
    #[account(
        init,
        payer = authority,
        space = 8 + 32 + 8, // discriminator + owner + balance
    )]
    pub user_account: Account<'info, UserAccount>,
    
    /// SECURE: Marked as signer - only they can initialize
    #[account(mut)]
    pub authority: Signer<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    /// The user account we're withdrawing from
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// SECURE: Must be a signer (intent verification)
    /// But we ALSO check they match the owner inside the function
    #[account(signer)]
    pub authority: Signer<'info>,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum CustomError {
    #[msg("Unauthorized: authority does not match owner")]
    Unauthorized,
    
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,
}
