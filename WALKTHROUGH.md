# Complete Walkthrough: Learning Solana Security

This document provides a guided walkthrough of each security example with explanations and learning objectives.

## Module 1: Missing Account Validation

**Location**: `programs/missing_account_validation/`

**Time to Review**: 15-20 minutes

### Learning Objective
Understand how Anchor's `#[account(...)]` constraints prevent passing wrong accounts to your program.

### The Vulnerability

**Problem**: The vulnerable code accepts any `AccountInfo` without validating it belongs to the correct token mint.

```rust
// VULNERABLE - any account can be passed
#[derive(Accounts)]
pub struct TransferUnsafe<'info> {
    #[account(mut)]
    pub token_from: AccountInfo<'info>,  // Could be ANYTHING
    
    #[account(mut)]
    pub token_to: AccountInfo<'info>,    // Could be ANYTHING
    
    pub authority: AccountInfo<'info>,   // Not even marked as signer!
}
```

**Attack**: An attacker could pass:
- Mint accounts instead of TokenAccounts
- Accounts from different programs
- Uninitialized accounts
- Accounts they don't own

**Result**: Program crashes, corrupts state, or behaves unexpectedly.

### The Fix

**Solution**: Use Anchor's `associated_token_account::mint` constraint:

```rust
// SECURE - constraints verify relationships
#[derive(Accounts)]
pub struct TransferSafe<'info> {
    pub mint: Account<'info, Mint>,
    
    #[account(
        mut,
        associated_token_account::mint = mint,  // MUST belong to this mint
    )]
    pub token_from: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token_account::mint = mint,  // MUST belong to this mint
    )]
    pub token_to: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub authority: Signer<'info>,  // MUST be a signer
    
    pub token_program: Program<'info, Token>,
}
```

**Key Changes**:
- Changed `AccountInfo` to `Account<'info, TokenAccount>`
- Added `associated_token_account::mint = mint` constraint
- Added signer verification
- Anchor automatically validates all constraints before instruction runs

### Key Concepts

- **Account Constraints**: The `#[account(...)]` macro checks properties before execution
- **Account Types**: `Account<'info, T>` specifies expected type (TokenAccount, Mint, etc.)
- **Relationships**: Constraints can validate relationships between accounts
- **Fail Fast**: Validation happens before your instruction code runs

### Try It Yourself

1. Read the vulnerable version:
   ```bash
   cat programs/missing_account_validation/src/vulnerable.rs
   ```

2. Notice the lack of constraints on `token_from` and `token_to`

3. Read the secure version:
   ```bash
   cat programs/missing_account_validation/src/secure.rs
   ```

4. Compare the `#[derive(Accounts)]` sections

---

## Module 2: Incorrect Authority Check

**Location**: `programs/incorrect_authority_check/`

**Time to Review**: 15-20 minutes

### Learning Objective
Understand that marking an account as a signer is NOT enough - you must also verify ownership.

### The Vulnerability

**Problem**: The vulnerable code checks that authority is a signer, but doesn't check if they actually own the account.

```rust
// VULNERABLE - signer but not owner check
pub fn withdraw_unsafe(
    ctx: Context<WithdrawUnsafe>,
    amount: u64,
) -> Result<()> {
    let account = &mut ctx.accounts.user_account;

    // PROBLEM: We don't verify authority is the OWNER!
    // Just being a signer doesn't mean they own this account
    
    require!(account.balance >= amount, CustomError::InsufficientFunds);
    account.balance -= amount;
    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawUnsafe<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    #[account(signer)]
    pub authority: AccountInfo<'info>,  // Signer? Yes. Owner? Unknown!
}
```

**Attack**: Attacker A could:
1. Steal User B's account
2. Sign with their own key (they're a signer)
3. Withdraw from User B's account
4. No verification that Attacker A = User B

**Result**: Any signer can drain anyone's account.

### The Fix

**Solution**: Explicitly verify `authority.key() == account.owner`:

```rust
// SECURE - explicit ownership check
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
    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    
    // Use Signer type instead of AccountInfo for clarity
    #[account(signer)]
    pub authority: Signer<'info>,
}
```

**Key Changes**:
- Added explicit `require_eq!` check comparing keys
- Changed to `Signer<'info>` type for clarity
- Now only the actual owner can withdraw

### Key Concepts

- **Signer ≠ Owner**: A transaction can be signed by anyone with a keypair
- **Explicit Checks**: Always compare `signer.key() == stored_owner`
- **Multiple Layers**: Mark as signer AND check ownership
- **Type Safety**: Use `Signer<'info>` to indicate expected signer

### Try It Yourself

1. Compare the two versions:
   ```bash
   diff \
     programs/incorrect_authority_check/src/vulnerable.rs \
     programs/incorrect_authority_check/src/secure.rs
   ```

2. Look for the `require_eq!` line - that's the key fix

3. Notice how the vulnerable version would allow anyone to withdraw

---

## Module 3: Unsafe Arithmetic

**Location**: `programs/unsafe_arithmetic/`

**Time to Review**: 15-20 minutes

### Learning Objective
Understand that unchecked arithmetic silently wraps and can corrupt state.

### The Vulnerability

**Problem**: Using `+`, `-`, `*` instead of checked operations causes silent overflow/underflow.

```rust
// VULNERABLE - unchecked arithmetic
pub fn deposit_unsafe(
    ctx: Context<DepositUnsafe>,
    amount: u64,
) -> Result<()> {
    let account = &mut ctx.accounts.pool;

    // PROBLEM: If total_deposited is u64::MAX and someone deposits 1,
    // this wraps to 0 instead of detecting overflow!
    account.total_deposited = account.total_deposited.wrapping_add(amount);

    // PROBLEM: If amount * fee_bps overflows, we get wrong result
    let reward_rate = 100u64;
    let rewards = amount.wrapping_mul(reward_rate);  // Could overflow!
    account.total_rewards = account.total_rewards.wrapping_add(rewards);

    Ok(())
}

pub fn withdraw_unsafe(
    ctx: Context<WithdrawUnsafe>,
    amount: u64,
) -> Result<()> {
    let account = &mut ctx.accounts.pool;

    // PROBLEM: If amount > total_available, this wraps to huge number!
    account.total_available = account.total_available.wrapping_sub(amount);
    
    Ok(())
}
```

**Attack**: Attacker could:
1. Deposit to make total_deposited = u64::MAX
2. Deposit 1 more - wraps to 0
3. Pool shows 0 balance but contains all funds
4. Or withdraw more than available - underflows

**Result**: Fund loss, state corruption, accounting errors.

### The Fix

**Solution**: Use `checked_*` operations that return `Option`:

```rust
// SECURE - checked arithmetic
pub fn deposit_safe(
    ctx: Context<DepositSafe>,
    amount: u64,
) -> Result<()> {
    let account = &mut ctx.accounts.pool;

    // SECURE: checked_add returns Option
    // If overflow, returns None and we error out
    account.total_deposited = account
        .total_deposited
        .checked_add(amount)
        .ok_or(CustomError::ArithmeticOverflow)?;

    // SECURE: checked multiplication
    let reward_rate = 100u64;
    let rewards = amount
        .checked_mul(reward_rate)
        .ok_or(CustomError::ArithmeticOverflow)?;
    
    account.total_rewards = account
        .total_rewards
        .checked_add(rewards)
        .ok_or(CustomError::ArithmeticOverflow)?;

    Ok(())
}

pub fn withdraw_safe(
    ctx: Context<WithdrawSafe>,
    amount: u64,
) -> Result<()> {
    let account = &mut ctx.accounts.pool;

    // SECURE: checked_sub returns None on underflow
    account.total_available = account
        .total_available
        .checked_sub(amount)
        .ok_or(CustomError::ArithmeticUnderflow)?;

    Ok(())
}
```

**Key Changes**:
- Changed `.wrapping_*` to `.checked_*`
- Use `.ok_or()` to convert `Option` to `Result`
- Use `?` to propagate errors

### Key Concepts

- **Checked Arithmetic**: Always use `checked_add`, `checked_sub`, `checked_mul`, `checked_div`
- **Option Type**: These return `Option<T>` - `Some(value)` or `None`
- **Error Propagation**: Use `?` to return error on overflow/underflow
- **Large Numbers**: Use `u128` for intermediate calculations if needed

### Try It Yourself

1. Search for `wrapping_` in vulnerable:
   ```bash
   grep -n "wrapping_" programs/unsafe_arithmetic/src/vulnerable.rs
   ```

2. Search for `checked_` in secure:
   ```bash
   grep -n "checked_" programs/unsafe_arithmetic/src/secure.rs
   ```

3. Count how many operations changed

---

## Module 4: CPI Misuse

**Location**: `programs/cpi_misuse/`

**Time to Review**: 20-25 minutes

### Learning Objective
Understand how to safely invoke other programs (CPI) without trust issues or corruption.

### The Vulnerability

**Problem**: CPI without validation of program ID, accounts, or error handling.

```rust
// VULNERABLE - unsafe CPI
pub fn unsafe_token_transfer(
    ctx: Context<TransferUnsafeCpi>,
    amount: u64,
) -> Result<()> {
    // PROBLEM 1: We don't verify token_program is the real token program!
    // Attacker could pass their own program
    
    // PROBLEM 2: Manual instruction construction is error-prone
    let transfer_instruction = anchor_lang::solana_program::instruction::Instruction {
        program_id: ctx.accounts.token_program.key(),
        accounts: vec![
            AccountMeta::new(ctx.accounts.from_token.key(), false),
            AccountMeta::new(ctx.accounts.to_token.key(), false),
            AccountMeta::new_readonly(ctx.accounts.authority.key(), true),
        ],
        data: vec![], // PROBLEM 3: Not properly formatted!
    };

    // PROBLEM 4: We don't check the return value!
    let _result = anchor_lang::solana_program::program::invoke_signed(
        &transfer_instruction,
        &[...],
        &[],
    );

    msg!("Transfer executed (but we didn't check if it succeeded!)");
    Ok(()) // Even if CPI FAILED, we return success!
}
```

**Attack**: Attacker could:
1. Pass fake token program
2. Pass wrong account relationships
3. Pass uninitialized accounts
4. We ignore return value so attack succeeds anyway

**Result**: Program state corruption, fund theft, system compromise.

### The Fix

**Solution**: Use Anchor's CPI helpers and verify program IDs:

```rust
// SECURE - safe CPI
pub fn safe_token_transfer(
    ctx: Context<TransferSafeCpi>,
    amount: u64,
) -> Result<()> {
    // SECURE: Verify this is the actual token program
    require_eq!(
        ctx.accounts.token_program.key(),
        spl_token::id(),  // Compare to known constant
        CustomError::InvalidTokenProgram
    );

    // SECURE: Use Anchor's CPI helper which:
    // 1. Constructs instruction correctly
    // 2. Validates account relationships
    // 3. Properly handles signers
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
    )?;  // SECURE: We check the Result!

    msg!("Token transfer completed successfully");
    Ok(())
}

// SECURE: Account struct with proper validation
#[derive(Accounts)]
pub struct TransferSafeCpi<'info> {
    #[account(mut)]
    pub from_token: Account<'info, TokenAccount>,
    
    #[account(mut)]
    pub to_token: Account<'info, TokenAccount>,
    
    pub authority: Signer<'info>,
    
    // SECURE: Using Program type verifies ownership
    pub token_program: Program<'info, Token>,
}
```

**Key Changes**:
- Verify program ID matches constant
- Use `CpiContext` not raw `invoke`
- Check return value with `?`
- Use Anchor's type-safe helpers
- Validate all account relationships

### Key Concepts

- **Program ID Verification**: Always compare to known constants
- **CpiContext**: Use high-level helpers instead of manual invoke
- **Error Handling**: Always propagate CPI errors
- **Account Validation**: Verify relationships before CPI
- **Signer Delegation**: Use proper seed-based signing

### Try It Yourself

1. Look at the difference in CPI calls:
   ```bash
   grep -A 20 "pub fn unsafe_token_transfer" programs/cpi_misuse/src/vulnerable.rs
   grep -A 20 "pub fn safe_token_transfer" programs/cpi_misuse/src/secure.rs
   ```

2. Notice: vulnerable uses `invoke_signed`, secure uses `token::transfer`

3. Count the `require_keys_eq!` checks in secure version

---

## Module 5: Reentrancy Risk

**Location**: `programs/reentrancy_risk/`

**Time to Review**: 20-25 minutes

### Learning Objective
Understand the Checks-Effects-Interactions (CEI) pattern and how to prevent reentrancy.

### The Vulnerability

**Problem**: State is updated AFTER external calls, allowing reentrancy.

```rust
// VULNERABLE - WRONG ORDER
pub fn withdraw_vulnerable(
    ctx: Context<WithdrawVulnerable>,
    amount: u64,
) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let user = &mut ctx.accounts.user_deposit;

    // CHECK: Verify preconditions
    require!(user.balance >= amount, CustomError::InsufficientBalance);

    // INTERACTION: External call FIRST - WRONG ORDER!
    // During this CPI, attacker can call back into our program
    // They'll see the balance unchanged (still has 100)
    token::transfer(
        CpiContext::new(...),
        amount,
    )?;

    // EFFECTS: Update state AFTER - TOO LATE!
    // By this time, attacker already called us again
    user.balance = user.balance.checked_sub(amount)?;
    pool.total_deposited = pool.total_deposited.checked_sub(amount)?;

    Ok(())
}
```

**Attack**: Reentrant call:
1. User withdraws 100
2. We check: balance = 100 ✓
3. We call token::transfer
4. During transfer, attacker re-enters: withdraw_vulnerable again!
5. We check: balance = 100 ✓ (not updated yet!)
6. We call token::transfer AGAIN
7. Finally update balance to 0
8. But attacker was paid twice!

**Result**: Fund drain, double spending, accounting errors.

### The Fix

**Solution**: Follow Checks-Effects-Interactions pattern:

```rust
// SECURE - CORRECT ORDER (CEI)
pub fn withdraw_safe(
    ctx: Context<WithdrawSafe>,
    amount: u64,
) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let user = &mut ctx.accounts.user_deposit;

    // PHASE 1: CHECKS - Verify preconditions
    require!(user.balance >= amount, CustomError::InsufficientBalance);
    require!(pool.total_available >= amount, CustomError::InsufficientPoolFunds);
    require!(!pool.locked, CustomError::PoolLocked);

    // PHASE 2: EFFECTS - Update state FIRST
    // Lock the pool (reentrancy guard)
    pool.locked = true;
    
    // Decrease balances IMMEDIATELY
    user.balance = user.balance.checked_sub(amount)?;
    pool.total_deposited = pool.total_deposited.checked_sub(amount)?;
    pool.total_available = pool.total_available.checked_sub(amount)?;

    // PHASE 3: INTERACTIONS - External calls LAST
    // Now if attacker re-enters, balance is already decreased
    token::transfer(
        CpiContext::new(...),
        amount,
    )?;

    // Unlock after successful transfer
    pool.locked = false;

    Ok(())
}

#[account]
pub struct PoolSafe {
    pub total_deposited: u64,
    pub total_available: u64,
    pub locked: bool,  // Reentrancy guard
}
```

**Key Changes**:
- Moved state updates (EFFECTS) BEFORE external calls (INTERACTIONS)
- Added `locked` field for reentrancy guard
- Check that pool isn't locked at start
- Update locked flag before and after transfer
- Now re-entry sees updated balance

### Key Concepts

- **CEI Pattern**: Checks → Effects → Interactions (in that order)
- **Update First**: State changes happen before external calls
- **Reentrancy Guards**: Use `locked` flag to prevent re-entry
- **Solana Advantage**: Can't call yourself directly, but other programs can call back
- **Call Stack**: Understand Solana's call stack model

### Try It Yourself

1. Compare the order of operations:
   ```bash
   grep -n "require!\|token::transfer\|user.balance =" programs/reentrancy_risk/src/vulnerable.rs | head -10
   grep -n "require!\|token::transfer\|user.balance =" programs/reentrancy_risk/src/secure.rs | head -10
   ```

2. Notice where `token::transfer` appears relative to balance updates

3. Look for the `locked` field in secure version

---

## Summary: Security Patterns

| Vulnerability | Root Cause | Fix Pattern |
|---------------|-----------|------------|
| Missing Account Validation | No account constraints | Use `#[account(...)]` macros |
| Incorrect Authority | Signer ≠ Owner check | `require_eq!(signer, owner)` |
| Unsafe Arithmetic | Using `+`, `-`, `*` | Use `checked_*` methods |
| CPI Misuse | No validation of external calls | Verify IDs, use helpers, check errors |
| Reentrancy | State after external calls | Checks → Effects → Interactions |

## Next Steps

1. **Build all programs**: `cargo build --release`
2. **Read SECURITY_PATTERNS.md**: Deep conceptual understanding
3. **Study each module**: Follow this walkthrough for each program
4. **Experiment**: Modify code and see what breaks
5. **Test**: Write test cases for each vulnerability
6. **Apply**: Use these patterns in your own programs

## Key Takeaways

1. **Anchor Constraints Save Lives**: Use them extensively
2. **Never Trust User Input**: Always validate accounts
3. **Checked Math**: Always use checked operations
4. **External Calls Are Dangerous**: Verify everything, handle errors
5. **Reentrancy is Real**: Order matters - effects before interactions

---

**Remember**: Understanding vulnerabilities is the best defense against introducing them!

For deep-dive concepts, see [SECURITY_PATTERNS.md](SECURITY_PATTERNS.md)
