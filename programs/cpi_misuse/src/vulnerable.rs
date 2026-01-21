use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// ============================================================================
// VULNERABILITY: CPI Misuse
// ============================================================================
//
// WHAT'S BROKEN:
// This program calls into other programs (CPI) without proper:
// - Account validation (wrong accounts could be passed)
// - Signer delegation verification
// - Return value checking
// - Account mutability requirements
//
// WHY IT'S UNSAFE:
// - Doesn't verify which program is being called
// - Passes mutable accounts without validating ownership
// - Ignores return values from CPI calls
// - Could call malicious programs with sensitive data
//
// SEVERITY: CRITICAL
// ============================================================================

declare_id!("44444444444444444444444444444444");

#[program]
pub mod cpi_misuse {
    use super::*;

    /// VULNERABLE: Performs CPI without proper validation
    pub fn unsafe_token_transfer(
        ctx: Context<TransferUnsafeCpi>,
        amount: u64,
    ) -> Result<()> {
        // VULNERABILITY: We don't verify token_program is actually
        // the legitimate Solana token program!
        // An attacker could pass a fake program and steal tokens
        
        let transfer_instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.from_token.key(), false),
                AccountMeta::new(ctx.accounts.to_token.key(), false),
                AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
            ],
            data: vec![], // VULNERABILITY: Not properly formatted
        };

        // VULNERABILITY: We don't check the return value!
        let _result = anchor_lang::solana_program::program::invoke_signed(
            &transfer_instruction,
            &[
                ctx.accounts.from_token.to_account_info(),
                ctx.accounts.to_token.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
            &[], // No proper signer seeds
        );

        msg!("Transfer executed (but we didn't check if it succeeded!)");
        Ok(()) // Even if CPI failed, we return success!
    }

    /// VULNERABLE: Unsafe delegation of signer
    pub fn unsafe_delegate_call(
        ctx: Context<DelegateUnsafe>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        // VULNERABILITY: We blindly invoke ANY program with ANY data!
        // This is extremely dangerous - the attacker controls what code runs
        
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.target_program.key(), // Could be ANYTHING
            accounts: vec![
                AccountMeta::new(ctx.accounts.user_data.key(), false),
                AccountMeta::new_readonly(ctx.accounts.owner.key(), false),
            ],
            data: instruction_data, // Attacker controls this!
        };

        anchor_lang::solana_program::program::invoke(
            &instruction,
            &[
                ctx.accounts.user_data.to_account_info(),
                ctx.accounts.owner.to_account_info(),
                ctx.accounts.target_program.to_account_info(),
            ],
        )?;

        msg!("Executed arbitrary instruction!");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TransferUnsafeCpi<'info> {
    #[account(mut)]
    pub from_token: AccountInfo<'info>,
    
    #[account(mut)]
    pub to_token: AccountInfo<'info>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
    
    /// VULNERABILITY: Not verified to be the real token program!
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DelegateUnsafe<'info> {
    #[account(mut)]
    pub user_data: AccountInfo<'info>,
    
    pub owner: AccountInfo<'info>,
    
    /// VULNERABILITY: Any program can be called!
    pub target_program: AccountInfo<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("CPI execution failed")]
    CpiFailed,
}
