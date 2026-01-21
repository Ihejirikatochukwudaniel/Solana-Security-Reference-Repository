use anchor_lang::prelude::*;

// ============================================================================
// VULNERABILITY: Missing Account Validation
// ============================================================================
// 
// WHAT'S BROKEN:
// This program transfers tokens without validating that the accounts passed
// actually belong to the expected token mint or are properly initialized.
// An attacker could pass arbitrary accounts, potentially draining tokens
// or manipulating program state unexpectedly.
//
// WHY IT'S UNSAFE:
// - No checks that 'token_from' and 'token_to' belong to the correct mint
// - No validation that accounts are initialized
// - An attacker could pass unrelated token accounts and corrupt state
// - Missing signer checks on certain accounts
//
// SEVERITY: CRITICAL
// ============================================================================

declare_id!("11111111111111111111111111111111");

#[program]
pub mod missing_account_validation {
    use super::*;

    /// VULNERABLE: Transfers tokens without proper account validation
    pub fn transfer_tokens_unsafe(
        ctx: Context<TransferUnsafe>,
        amount: u64,
    ) -> Result<()> {
        // VULNERABILITY: We accept any token account without checking:
        // 1. That token_from belongs to the correct mint
        // 2. That token_to belongs to the correct mint
        // 3. That token_from has enough balance (though we check later)
        // 4. Account ownership or initialization status

        let from_account = &ctx.accounts.token_from;
        let to_account = &ctx.accounts.token_to;

        // Dangerously assume these are valid token accounts and transfer
        // In reality, we should use anchor_spl token_transfer helper
        // or manually validate account structure
        
        msg!("Transferring {} tokens", amount);
        
        // This would fail at runtime but demonstrates the principle:
        // We're not validating the account structure at all
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferUnsafe<'info> {
    /// VULNERABILITY: No validation that this is from the correct mint
    #[account(mut)]
    pub token_from: AccountInfo<'info>,
    
    /// VULNERABILITY: No validation that this is to the correct mint
    #[account(mut)]
    pub token_to: AccountInfo<'info>,
    
    /// The authority - but we don't verify they signed!
    pub authority: AccountInfo<'info>,
}
