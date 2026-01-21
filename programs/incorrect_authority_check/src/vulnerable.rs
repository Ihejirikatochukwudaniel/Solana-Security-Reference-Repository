use anchor_lang::prelude::*;

// ============================================================================
// VULNERABILITY: Incorrect Authority Check
// ============================================================================
//
// WHAT'S BROKEN:
// This program fails to properly verify who is authorized to perform
// sensitive operations. An attacker could impersonate the owner or
// manipulate accounts because the authority check is either missing,
// incomplete, or checks the wrong account.
//
// WHY IT'S UNSAFE:
// - Authority is not marked as a signer (could be anyone)
// - No validation that the authority matches the stored owner
// - No ownership verification before state changes
// - Permission model is implicit and easy to bypass
//
// SEVERITY: CRITICAL
// ============================================================================

declare_id!("22222222222222222222222222222222");

#[program]
pub mod incorrect_authority_check {
    use super::*;

    /// VULNERABLE: Initialize account without proper authority setup
    pub fn initialize_unsafe(
        ctx: Context<InitializeUnsafe>,
        initial_amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.user_account;
        
        // VULNERABILITY: We don't verify who is initializing this!
        // We just set an owner, but never check if the caller is authorized
        // Anyone can initialize and claim ownership of accounts
        
        account.owner = ctx.accounts.authority.key();
        account.balance = initial_amount;

        msg!("Account initialized with owner: {}", account.owner);
        Ok(())
    }

    /// VULNERABLE: Withdraw without checking authority
    pub fn withdraw_unsafe(
        ctx: Context<WithdrawUnsafe>,
        amount: u64,
    ) -> Result<()> {
        let account = &mut ctx.accounts.user_account;

        // VULNERABILITY: We don't verify the authority is actually the owner!
        // Just because someone passed `authority` doesn't mean they own this account
        // An attacker could pass their own account as `authority` and steal funds
        
        require!(account.balance >= amount, CustomError::InsufficientFunds);
        
        account.balance -= amount;
        
        // Emit a fake transfer
        msg!("Withdrew {} SOL", amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeUnsafe<'info> {
    /// The user account to initialize
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// VULNERABILITY: Not marked as signer, could be anyone!
    pub authority: AccountInfo<'info>,
    
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawUnsafe<'info> {
    /// The user account we're withdrawing from
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    /// VULNERABILITY: Not verified to be the owner of user_account
    /// Just checking that it's a signer is not enough!
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum CustomError {
    #[msg("Insufficient funds")]
    InsufficientFunds,
}
