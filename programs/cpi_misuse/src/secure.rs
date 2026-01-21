use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

// ============================================================================
// FIX: Safe CPI Patterns
// ============================================================================
//
// WHAT'S FIXED:
// This version implements safe CPI practices:
// - Verifies the program being called is the expected program
// - Uses Anchor's CPI helpers instead of raw invoke
// - Checks return values from CPI calls
// - Proper signer delegation with seeds
//
// BEST PRACTICES:
// 1. Always verify program IDs match constants
// 2. Use CpiContext for high-level helpers
// 3. Check return values from all CPI calls
// 4. Use PDA seeds for signer delegation
// 5. Validate account ownership and state before CPI
//
// ============================================================================

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("44444444444444444444444444444444");

// SECURE: Define known trusted program IDs as constants
// This prevents attacker from passing arbitrary program IDs
const TRUSTED_PROGRAM_ID: &str = "11111111111111111111111111111111"; // Example trusted program

#[program]
pub mod cpi_misuse_secure {
    use super::*;

    /// SECURE: Properly validates and executes CPI
    pub fn safe_token_transfer(
        ctx: Context<TransferSafeCpi>,
        amount: u64,
    ) -> Result<()> {
        // SECURE: Verify this is the actual token program
        // by checking against a known constant
        require_eq!(
            ctx.accounts.token_program.key(),
            spl_token::id(),
            CustomError::InvalidTokenProgram
        );

        // SECURE: Use Anchor's CpiContext which handles the invoke for us
        // and ensures proper account validation
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from_token.to_account_info(),
                    to: ctx.accounts.to_token.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                },
            ),
            amount,
        )?; // SECURE: We check the Result from the CPI

        msg!("Token transfer completed successfully");
        Ok(())
    }

    /// SECURE: Delegate to known program with validation
    pub fn safe_delegate_call(
        ctx: Context<DeligateSafe>,
        instruction_data: Vec<u8>,
    ) -> Result<()> {
        // SECURE: Verify the target program is one we expect
        require_keys_eq!(
            ctx.accounts.target_program.key(),
            TRUSTED_PROGRAM_ID, // Must be a constant defined by us
            CustomError::UntrustedProgram
        );

        // SECURE: Verify the user_data account is owned by the target program
        require_keys_eq!(
            ctx.accounts.user_data.owner,
            TRUSTED_PROGRAM_ID,
            CustomError::WrongAccountOwner
        );

        // Construct instruction safely
        let instruction = anchor_lang::solana_program::instruction::Instruction {
            program_id: ctx.accounts.target_program.key(),
            accounts: vec![
                AccountMeta::new(ctx.accounts.user_data.key(), false),
                AccountMeta::new_readonly(ctx.accounts.owner.key(), false),
            ],
            data: instruction_data,
        };

        // SECURE: Invoke and handle the result
        let result = anchor_lang::solana_program::program::invoke(
            &instruction,
            &[
                ctx.accounts.user_data.to_account_info(),
                ctx.accounts.owner.to_account_info(),
                ctx.accounts.target_program.to_account_info(),
            ],
        );

        // SECURE: Check if the instruction succeeded
        match result {
            Ok(_) => {
                msg!("Successfully executed delegated instruction");
                Ok(())
            }
            Err(e) => {
                msg!("CPI failed: {:?}", e);
                Err(CustomError::CpiFailed.into())
            }
        }
    }

    /// SECURE: CPI with PDA signer delegation
    pub fn safe_delegate_with_pda(
        ctx: Context<DelegateWithPda>,
        bump: u8,
        amount: u64,
    ) -> Result<()> {
        // SECURE: Verify the PDA was derived correctly
        let seeds = b"trusted_seed".as_ref();
        let pda = Pubkey::find_program_address(&[seeds], &crate::ID()).0;
        
        require_keys_eq!(
            ctx.accounts.pda_signer.key(),
            pda,
            CustomError::InvalidPdaSigner
        );

        // SECURE: Use PDA as signer in CPI
        let signer_seeds: &[&[&[u8]]] = &[&[b"trusted_seed".as_ref(), &[bump]]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.from_token.to_account_info(),
                    to: ctx.accounts.to_token.to_account_info(),
                    authority: ctx.accounts.pda_signer.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )?;

        msg!("PDA-signed transfer completed successfully");
        Ok(())
    }
}

// Known trusted program - change this to your actual trusted program
pub const TRUSTED_PROGRAM_ID: Pubkey = Pubkey::new_from_array([0; 32]); // Placeholder

#[derive(Accounts)]
pub struct TransferSafeCpi<'info> {
    #[account(mut)]
    pub from_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_token: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    /// SECURE: We verify this is the token program
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct DeligateSafe<'info> {
    #[account(mut)]
    pub user_data: AccountInfo<'info>,
    
    pub owner: Signer<'info>,
    
    /// SECURE: We verify this is a trusted program
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DelegateWithPda<'info> {
    #[account(mut)]
    pub from_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_token: Account<'info, TokenAccount>,
    
    /// PDA that acts as signer
    pub pda_signer: AccountInfo<'info>,
    
    pub token_program: Program<'info, Token>,
}

#[error_code]
pub enum CustomError {
    #[msg("Invalid token program")]
    InvalidTokenProgram,
    
    #[msg("Untrusted program")]
    UntrustedProgram,
    
    #[msg("Wrong account owner")]
    WrongAccountOwner,
    
    #[msg("CPI execution failed")]
    CpiFailed,
    
    #[msg("Invalid PDA signer")]
    InvalidPdaSigner,
}
