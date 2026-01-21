# Solana Security Patterns - Deep Dive

A comprehensive guide to understanding Solana security concepts, account models, and best practices.

## Table of Contents

1. [Solana Account Model Fundamentals](#solana-account-model-fundamentals)
2. [Authority and Permission Patterns](#authority-and-permission-patterns)
3. [Safe Arithmetic Operations](#safe-arithmetic-operations)
4. [Cross-Program Invocation (CPI) Safety](#cross-program-invocation-cpi-safety)
5. [Reentrancy and Call Stack](#reentrancy-and-call-stack)
6. [Anchor Framework Constraints](#anchor-framework-constraints)
7. [Security Checklist](#security-checklist)
8. [Real-World Attack Examples](#real-world-attack-examples)

---

## Solana Account Model Fundamentals

### What is an Account?

In Solana, accounts are the fundamental data structures. Unlike Ethereum's contract-based state, Solana programs are **stateless** - all data lives in accounts.

Every account has:
- **Address**: Public key identifying the account
- **Owner**: Program that can modify the account's data
- **Data**: Raw bytes storing the account's state
- **Lamports**: SOL balance in the account
- **Executable**: Flag indicating if it's a program account

```rust
// Account structure in Anchor
#[derive(Accounts)]
pub struct MyContext<'info> {
    #[account(mut)]
    pub user_data: Account<'info, UserData>,  // Can be modified
    pub system_program: Program<'info, System>, // Immutable
}
```

### Ownership Rules

**Critical Rule**: Only the owner program can modify an account's data.

```rust
// ❌ WRONG: Trying to modify account you don't own
pub fn bad_transfer(ctx: Context<BadTransfer>) -> Result<()> {
    // This will fail - you don't own other_program_account
    let data = &mut ctx.accounts.other_program_account.try_borrow_mut_data()?;
    // Cannot modify!
    Ok(())
}

// ✅ CORRECT: Only modify your own accounts
pub fn good_update(ctx: Context<GoodUpdate>) -> Result<()> {
    let my_data = &mut ctx.accounts.my_account;
    my_data.value = 42; // OK - you own this account
    Ok(())
}
```

### The Account Lifecycle

```
1. Account Created
   └─ Initialized with data
   └─ Owner set (usually your program)
   
2. Account Exists
   └─ Only owner can modify data
   └─ Anyone can read data
   
3. Account Closed (Optional)
   └─ Lamports sent to some account
   └─ Data zeroed out or reallocated
```

---

## Authority and Permission Patterns

### The Signer Concept

In Solana, a transaction must be signed by private keys. The signatures prove authorization.

```rust
// ❌ VULNERABLE: Not checking if authority signed
pub fn vulnerable_withdraw(
    ctx: Context<WithdrawVulnerable>,
    amount: u64,
) -> Result<()> {
    // authority could be anyone! No signature verification!
    let account = &mut ctx.accounts.user_account;
    account.balance = account.balance.checked_sub(amount)
        .ok_or(error!(CustomError::InsufficientFunds))?;
    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawVulnerable<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    pub authority: AccountInfo<'info>,  // NOT a signer!
}

// ✅ SECURE: Verifying signer
pub fn secure_withdraw(
    ctx: Context<WithdrawSecure>,
    amount: u64,
) -> Result<()> {
    // Anchor guarantees authority is a signer via the Signer type
    let account = &mut ctx.accounts.user_account;
    account.balance = account.balance.checked_sub(amount)
        .ok_or(error!(CustomError::InsufficientFunds))?;
    
    msg!("Withdrew {} from {}", amount, ctx.accounts.authority.key());
    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawSecure<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    #[account(signer)]  // Anchor verifies this is a signer
    pub authority: Signer<'info>,
}
```

### Ownership Verification

Just because someone is a signer doesn't mean they own an account. Always verify ownership.

```rust
// ❌ VULNERABLE: Trusting authority without ownership check
pub fn steal_funds(ctx: Context<StealFunds>) -> Result<()> {
    // authority signed, but are they the owner?
    ctx.accounts.victim_account.owner = ctx.accounts.authority.key();
    Ok(())
}

// ✅ SECURE: Verify owner before allowing changes
pub fn transfer_ownership(ctx: Context<TransferOwnership>) -> Result<()> {
    // Verify authority is the current owner
    require_eq!(
        ctx.accounts.account.owner,
        ctx.accounts.authority.key(),
        CustomError::NotOwner
    );
    
    // Now safe to transfer
    ctx.accounts.account.owner = ctx.accounts.new_owner.key();
    msg!("Ownership transferred to {}", ctx.accounts.new_owner.key());
    Ok(())
}
```

### Role-Based Access Control (RBAC)

```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub enum Role {
    Admin,
    Moderator,
    User,
}

#[account]
pub struct UserProfile {
    pub owner: Pubkey,
    pub role: Role,
    pub balance: u64,
}

// ✅ SECURE: Role-based authorization
pub fn admin_action(
    ctx: Context<AdminAction>,
) -> Result<()> {
    require_eq!(
        ctx.accounts.profile.role,
        Role::Admin,
        CustomError::UnauthorizedRole
    );
    
    // Proceed with admin action
    msg!("Admin action executed by {}", ctx.accounts.authority.key());
    Ok(())
}

pub fn require_role(profile: &UserProfile, required_role: Role) -> Result<()> {
    match (&profile.role, required_role) {
        (Role::Admin, _) => Ok(()), // Admin can do anything
        (Role::Moderator, Role::Moderator) => Ok(()),
        (Role::Moderator, Role::User) => Ok(()),
        (Role::User, Role::User) => Ok(()),
        _ => Err(error!(CustomError::UnauthorizedRole)),
    }
}
```

---

## Safe Arithmetic Operations

### The Overflow Problem

Rust integers don't automatically overflow like JavaScript. Without `checked_*` methods, they panic.

```rust
// ❌ VULNERABLE: Unchecked arithmetic can panic or cause issues
pub fn unsafe_add(ctx: Context<UnsafeAdd>, amount: u64) -> Result<()> {
    // This panics if balance + amount overflows
    ctx.accounts.user.balance = ctx.accounts.user.balance + amount;
    Ok(())
}

// ✅ SECURE: Use checked arithmetic
pub fn safe_add(ctx: Context<SafeAdd>, amount: u64) -> Result<()> {
    ctx.accounts.user.balance = ctx.accounts.user.balance
        .checked_add(amount)
        .ok_or(error!(CustomError::Overflow))?;
    Ok(())
}

// ✅ ALSO SECURE: Saturating arithmetic for specific use cases
pub fn saturating_add(ctx: Context<SaturatingAdd>, amount: u64) -> Result<()> {
    // Caps at u64::MAX instead of panicking
    ctx.accounts.user.balance = ctx.accounts.user.balance.saturating_add(amount);
    Ok(())
}
```

### The Underflow Problem

```rust
// ❌ VULNERABLE: Underflow not checked
pub fn vulnerable_withdraw(ctx: Context<VulnerableWithdraw>, amount: u64) -> Result<()> {
    // If balance < amount, this underflows! (wraps around to huge number)
    ctx.accounts.user.balance -= amount;
    Ok(())
}

// ✅ SECURE: Check before subtracting
pub fn secure_withdraw(ctx: Context<SecureWithdraw>, amount: u64) -> Result<()> {
    ctx.accounts.user.balance = ctx.accounts.user.balance
        .checked_sub(amount)
        .ok_or(error!(CustomError::InsufficientFunds))?;
    Ok(())
}
```

### Safe Multiplication

```rust
// ❌ VULNERABLE: Multiplication overflow
pub fn calculate_fee(amount: u64, fee_bps: u64) -> Result<u64> {
    // If amount * fee_bps overflows u64, we have problems
    Ok(amount * fee_bps / 10000)
}

// ✅ SECURE: Checked multiplication
pub fn calculate_fee_safe(amount: u64, fee_bps: u64) -> Result<u64> {
    let fee = amount
        .checked_mul(fee_bps)
        .ok_or(error!(CustomError::Overflow))?
        .checked_div(10000)
        .ok_or(error!(CustomError::InvalidFee))?;
    Ok(fee)
}

// ✅ BETTER: Use u128 for intermediate calculations
pub fn calculate_fee_better(amount: u64, fee_bps: u64) -> Result<u64> {
    let amount_u128 = amount as u128;
    let fee_bps_u128 = fee_bps as u128;
    
    let fee_u128 = amount_u128
        .checked_mul(fee_bps_u128)
        .ok_or(error!(CustomError::Overflow))?
        .checked_div(10000)
        .ok_or(error!(CustomError::InvalidFee))?;
    
    u64::try_from(fee_u128)
        .map_err(|_| error!(CustomError::Overflow))
}
```

### Precision Loss in Division

```rust
// ⚠️ WARNING: Order matters for precision
pub fn distribute_rewards(total_reward: u64, num_users: u64) -> Result<u64> {
    // ❌ BAD: Loses precision if total_reward < num_users
    let per_user_bad = total_reward / num_users;
    
    // ✅ BETTER: Calculate total distributed, keep remainder
    let per_user = total_reward / num_users;
    let remainder = total_reward % num_users;
    
    // Distribute remainder to first users or pool it
    msg!("Per user: {}, remainder: {}", per_user, remainder);
    
    Ok(per_user)
}
```

---

## Cross-Program Invocation (CPI) Safety

### What is CPI?

CPI allows your program to call another program. It's like function calls across programs.

```rust
// CPI transfers 100 tokens from user to recipient
pub fn cpi_transfer(ctx: Context<TransferViaToken>, amount: u64) -> Result<()> {
    let cpi_accounts = Transfer {
        from: ctx.accounts.from_token.to_account_info(),
        to: ctx.accounts.to_token.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_program = ctx.accounts.token_program.to_account_info();
    
    token::transfer(
        CpiContext::new(cpi_program, cpi_accounts),
        amount,
    )?;
    
    Ok(())
}
```

### Common CPI Mistakes

#### Mistake 1: Wrong Account Passed to CPI

```rust
// ❌ VULNERABLE: Passing wrong accounts to token::transfer
pub fn bad_transfer(ctx: Context<BadTransfer>) -> Result<()> {
    // If attacker passes any arbitrary account as 'from'
    // And doesn't validate it belongs to the right mint
    // Token program might accept it if it's writable
    
    let cpi_accounts = Transfer {
        from: ctx.accounts.attacker_account.to_account_info(), // Wrong!
        to: ctx.accounts.recipient.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
        amount,
    )?;
    
    Ok(())
}

// ✅ SECURE: Validate accounts have correct relationships
pub fn good_transfer(ctx: Context<GoodTransfer>) -> Result<()> {
    // Anchor ensures:
    // 1. from and to belong to the correct mint (via constraints)
    // 2. Both are properly initialized token accounts
    // 3. authority is a valid signer
    
    let cpi_accounts = Transfer {
        from: ctx.accounts.from.to_account_info(),
        to: ctx.accounts.to.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    
    token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
        amount,
    )?;
    
    Ok(())
}

#[derive(Accounts)]
pub struct GoodTransfer<'info> {
    pub mint: Account<'info, Mint>,
    
    #[account(mut, token::mint = mint)]
    pub from: Account<'info, TokenAccount>,
    
    #[account(mut, token::mint = mint)]
    pub to: Account<'info, TokenAccount>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
    
    pub token_program: Program<'info, Token>,
}
```

#### Mistake 2: Forgetting to Pass Signers

```rust
// ❌ VULNERABLE: CPI doesn't include required signer
pub fn bad_cpi_with_signer(ctx: Context<BadCpiSigner>) -> Result<()> {
    let cpi_accounts = SomeInstruction {
        authority: ctx.accounts.authority.to_account_info(),
        // ...
    };
    
    let cpi_program = ctx.accounts.program.to_account_info();
    
    // If the instruction requires authority to be a signer,
    // this will fail because authority isn't in the accounts array properly
    msg!("Error: This CPI will fail if program requires a signer!");
    
    Ok(())
}

// ✅ SECURE: Include signers in CPI context
pub fn good_cpi_with_signer(ctx: Context<GoodCpiSigner>) -> Result<()> {
    let cpi_accounts = SomeInstruction {
        authority: ctx.accounts.authority.to_account_info(),
        // ...
    };
    
    let cpi_program = ctx.accounts.program.to_account_info();
    
    // Create CPI context with the proper signer seeds if needed
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
    
    // If your program is a PDA signer, use:
    // let seeds = &[b"seed".as_ref(), &[bump_seed]];
    // let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, &[seeds]);
    
    Ok(())
}
```

#### Mistake 3: Not Validating CPI Return Values

```rust
// ❌ VULNERABLE: Ignoring CPI errors
pub fn bad_ignore_errors(ctx: Context<BadIgnore>) -> Result<()> {
    let result = token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
        amount,
    );
    
    // Just ignoring the error and continuing!
    // The transfer might have failed but we proceed
    msg!("Transfer completed"); // Maybe it didn't!
    
    Ok(())
}

// ✅ SECURE: Always handle CPI errors
pub fn good_handle_errors(ctx: Context<GoodHandle>) -> Result<()> {
    token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts),
        amount,
    )?;  // ← The ? operator propagates errors
    
    msg!("Transfer completed successfully");
    Ok(())
}
```

### CPI Security Checklist

1. **Validate all account constraints** - Use Anchor's `#[account(...)]` macros
2. **Verify account ownership** - Accounts must be owned by expected programs
3. **Check account mutability** - Only pass mutable accounts if the instruction writes
4. **Include required signers** - Pass all signer accounts in CPI
5. **Handle errors** - Don't ignore CPI return values
6. **Re-check balances after CPI** - Don't assume state changes worked

---

## Reentrancy and Call Stack

### Understanding Solana's Call Stack

Solana differs from Ethereum in a critical way: **The same contract cannot call itself during execution**.

This is because when you call into a program during transaction execution, that program's code is loaded into memory. You cannot have it load and re-execute while it's already executing.

However, **reentrancy through other programs is still possible**.

```rust
// SCENARIO: Program A calls Program B calls Program A
// 
// This IS possible in Solana:
// 1. User calls Program A
// 2. Program A makes CPI to Program B  
// 3. Program B makes CPI back to Program A (via CpiContext::new)
// 4. This SECOND call to Program A happens in the SAME transaction
// 5. If not careful, Program A's state can be modified unexpectedly

// ❌ VULNERABLE: Reentrancy risk
pub fn vulnerable_transfer_out(ctx: Context<VulnerableTransfer>) -> Result<()> {
    let account = &mut ctx.accounts.state;
    
    // Check balance
    if account.balance >= 100 {
        // BEFORE we update the balance, we call another program
        // If that program calls back here, balance is still 100!
        ctx.accounts.token_account.balance -= 100;
        
        // Make a CPI call - attacker's program receives control here
        make_external_call(ctx)?;  // ← Attacker could call back to this program
        
        // Now decrease our state
        // But attacker might have already called this function again!
        account.balance = account.balance.checked_sub(100)?;
    }
    
    Ok(())
}

// ✅ SECURE: Checks-Effects-Interactions pattern
pub fn secure_transfer_out(ctx: Context<SecureTransfer>) -> Result<()> {
    let account = &mut ctx.accounts.state;
    
    // 1. CHECKS: Verify preconditions
    if account.balance < 100 {
        return Err(error!(CustomError::InsufficientFunds));
    }
    
    // 2. EFFECTS: Update internal state FIRST
    account.balance = account.balance.checked_sub(100)?;
    
    // 3. INTERACTIONS: Only then make external calls
    // Now even if re-entered, the balance is already decreased
    make_external_call(ctx)?;
    
    Ok(())
}
```

### Attack Scenario: Draining Funds

```rust
// ATTACKER'S FLOW:
// 1. Attacker's program calls Victim program: "withdraw 1 SOL"
// 2. Victim program (vulnerable): Checks balance (1000 SOL available)
// 3. Victim transfers 1 SOL... via CPI
// 4. During CPI, attacker's program re-enters Victim: "withdraw 1 SOL"
// 5. Victim checks balance again (still 1000! Not updated yet)
// 6. Victim transfers 1 SOL again
// 7. This repeats many times in same transaction
// 8. Result: Attacker drained multiple SOLs using single withdrawal

// ❌ VULNERABLE: Classic reentrancy
pub fn withdraw_vulnerable(ctx: Context<WithdrawVulnerable>, amount: u64) -> Result<()> {
    let balance = ctx.accounts.state.balance;
    
    if balance >= amount {
        // Transfer BEFORE updating state - reentrancy window!
        send_lamports(&ctx.accounts.recipient, amount)?;
        
        ctx.accounts.state.balance -= amount;
    }
    
    Ok(())
}

// ✅ SECURE: Update state before external calls
pub fn withdraw_secure(ctx: Context<WithdrawSecure>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    require_gte!(state.balance, amount, CustomError::InsufficientFunds);
    
    // Update FIRST
    state.balance = state.balance.checked_sub(amount)?;
    
    // THEN transfer
    send_lamports(&ctx.accounts.recipient, amount)?;
    
    Ok(())
}
```

### Prevention Strategies

```rust
// Strategy 1: Update state before external calls (Checks-Effects-Interactions)
pub fn strategy_1_safe(ctx: Context<Safe1>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    // 1. CHECKS
    require_gte!(state.balance, amount, CustomError::InsufficientFunds);
    
    // 2. EFFECTS
    state.balance -= amount;
    
    // 3. INTERACTIONS
    external_call()?;
    
    Ok(())
}

// Strategy 2: Use reentrancy guards (locks)
#[account]
pub struct LockedState {
    pub balance: u64,
    pub locked: bool,  // Reentrancy guard
}

pub fn strategy_2_safe(ctx: Context<Safe2>, amount: u64) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    // Check not already locked
    require!(!state.locked, CustomError::Locked);
    
    // Acquire lock
    state.locked = true;
    
    // Do work
    state.balance = state.balance.checked_sub(amount)?;
    external_call()?;
    
    // Release lock
    state.locked = false;
    
    Ok(())
}

// Strategy 3: Use PDA accounts to track state
#[account]
pub struct UserWithdrawalState {
    pub user: Pubkey,
    pub withdrawn_amount: u64,
    pub last_withdrawal_slot: u64,
}

pub fn strategy_3_safe(ctx: Context<Safe3>, amount: u64) -> Result<()> {
    let current_slot = Clock::get()?.slot;
    let state = &mut ctx.accounts.withdrawal_state;
    
    // Only allow one withdrawal per slot
    require_neq!(state.last_withdrawal_slot, current_slot, CustomError::AlreadyWithdrawnThisSlot);
    
    state.withdrawn_amount += amount;
    state.last_withdrawal_slot = current_slot;
    
    external_call()?;
    
    Ok(())
}
```

---

## Anchor Framework Constraints

### What Are Constraints?

Constraints are Anchor macros that automatically validate account properties before your instruction code runs.

```rust
// Without constraints, you'd have to manually check everything:
pub fn manual_checks(ctx: Context<Manual>) -> Result<()> {
    require!(
        ctx.accounts.pda_account.owner == &crate::ID,
        CustomError::InvalidOwner
    );
    require!(
        *ctx.accounts.pda_account.owner == ctx.accounts.pda_account.data_is_empty() == false,
        CustomError::NotInitialized
    );
    // ... more checks
    Ok(())
}

// With Anchor constraints, it's declarative:
#[derive(Accounts)]
pub struct Automatic<'info> {
    #[account(
        mut,
        seeds = [b"profile", user.key().as_ref()],
        bump,
        owner = crate::ID,
    )]
    pub pda_account: Account<'info, MyData>,
    pub user: Signer<'info>,
}
```

### Common Constraints

```rust
#[derive(Accounts)]
pub struct ExampleConstraints<'info> {
    // Account mutability
    #[account(mut)]
    pub mutable_account: AccountInfo<'info>,
    
    // Signer requirement
    #[account(signer)]
    pub signer: AccountInfo<'info>,
    
    // Or use Signer type (preferred)
    pub authority: Signer<'info>,
    
    // Owner check
    #[account(owner = crate::ID)]
    pub my_account: AccountInfo<'info>,
    
    // PDA verification
    #[account(
        seeds = [b"seed", user.key().as_ref()],
        bump,
    )]
    pub derived_account: Account<'info, MyData>,
    
    // Token account association
    #[account(token::mint = mint)]
    pub token_account: Account<'info, TokenAccount>,
    
    // Token mint relationship
    pub mint: Account<'info, Mint>,
    
    // Associated token account
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = user,
    )]
    pub user_token_account: Account<'info, TokenAccount>,
    
    // Reallocation for space increase
    #[account(
        mut,
        realloc = 1000,
        realloc::payer = payer,
        realloc::zero = true,
    )]
    pub resizable_account: Account<'info, MyData>,
    
    // Require specific value
    #[account(address = Pubkey::from_str("11111111111111111111111111111111")?)]
    pub specific_account: AccountInfo<'info>,
}
```

### Custom Constraints

```rust
// ✅ SECURE: Custom validation logic
#[derive(Accounts)]
pub struct CustomConstraint<'info> {
    #[account(
        mut,
        constraint = state.owner == authority.key() @ CustomError::NotOwner,
        constraint = state.balance > 0 @ CustomError::EmptyBalance,
    )]
    pub state: Account<'info, State>,
    
    #[account(signer)]
    pub authority: Signer<'info>,
}

#[account]
pub struct State {
    pub owner: Pubkey,
    pub balance: u64,
}
```

---

## Security Checklist

Use this checklist when writing Solana programs:

### Accounts & Ownership
- [ ] All account types properly declared with correct types
- [ ] Account owner verified where necessary (`@account(owner = ...)`)
- [ ] Signers marked with `#[account(signer)]` or `Signer<'info>`
- [ ] Mutable accounts marked with `#[account(mut)]`
- [ ] No accounts can be modified unexpectedly
- [ ] PDA bumps verified or auto-derived with Anchor

### Authority & Permissions
- [ ] All state-modifying instructions require proper authorization
- [ ] Ownership verified before ownership transfers
- [ ] Role-based access implemented for multi-role scenarios
- [ ] No authority checks that can be bypassed

### Arithmetic
- [ ] All additions use `.checked_add()` not `+`
- [ ] All subtractions use `.checked_sub()` not `-`
- [ ] All multiplications use `.checked_mul()` not `*`
- [ ] All divisions use `.checked_div()` not `/`
- [ ] Large intermediate calculations use u128 to prevent overflow

### CPI Safety
- [ ] All CPI account relationships validated via constraints
- [ ] CPI return values handled (not ignored with `;`)
- [ ] All required signer accounts included in CPI
- [ ] External program address verified (not user-supplied)
- [ ] CPI account types match what called program expects

### Reentrancy
- [ ] State updated BEFORE external calls (Checks-Effects-Interactions)
- [ ] Reentrancy guards considered if necessary
- [ ] Critical sections protected from re-entry
- [ ] Transaction ordering considered for race conditions

### General
- [ ] No panics in production code (use `?` and `Result`)
- [ ] Error messages are specific and helpful
- [ ] No unwrap() or expect() without careful consideration
- [ ] Complex state changes wrapped in transaction
- [ ] Integer sizes match expected value ranges

---

## Real-World Attack Examples

### Attack 1: Missing Owner Check

```rust
// ❌ VULNERABLE: No owner verification
pub fn withdraw_anyone_can(ctx: Context<WithdrawBad>, amount: u64) -> Result<()> {
    // Anyone can call this and withdraw from anyone's account!
    ctx.accounts.user_account.balance -= amount;
    Ok(())
}

// ✅ FIXED: Verify owner
pub fn withdraw_owner_only(ctx: Context<WithdrawGood>, amount: u64) -> Result<()> {
    require_eq!(
        ctx.accounts.user_account.owner,
        ctx.accounts.authority.key(),
        CustomError::NotOwner
    );
    ctx.accounts.user_account.balance -= amount;
    Ok(())
}
```

### Attack 2: Integer Overflow in Fee Calculation

```rust
// ❌ VULNERABLE: 
// If fee_bps = 10000 (100%) and amount = u64::MAX
// amount * fee_bps will overflow
pub fn calculate_fee_overflow(amount: u64, fee_bps: u64) -> Result<u64> {
    Ok(amount * fee_bps / 10000)
}

// ✅ FIXED: Safe calculation with u128
pub fn calculate_fee_safe(amount: u64, fee_bps: u64) -> Result<u64> {
    let fee = (amount as u128)
        .checked_mul(fee_bps as u128)?
        .checked_div(10000)?;
    Ok(fee as u64)
}
```

### Attack 3: Reentrancy Fund Drain

See "Reentrancy and Call Stack" section above for detailed scenario.

### Attack 4: Type Confusion

```rust
// ❌ VULNERABLE: Accepting any account that's owned by token program
pub fn transfer_with_any_account(
    ctx: Context<AnyAccount>,
    amount: u64,
) -> Result<()> {
    // Attacker passes a Mint account where TokenAccount expected
    // Mint and TokenAccount have different structures!
    let account = &ctx.accounts.token_account;
    // Interpreting Mint data as TokenAccount = corrupted state
    Ok(())
}

// ✅ FIXED: Strict type checking
pub fn transfer_strict_types(
    ctx: Context<StrictTypes>,
    amount: u64,
) -> Result<()> {
    // Anchor ensures token_account is actually a TokenAccount
    // And belongs to the correct mint
    Ok(())
}

#[derive(Accounts)]
pub struct StrictTypes<'info> {
    pub mint: Account<'info, Mint>,
    #[account(token::mint = mint)]  // Only TokenAccounts for this mint
    pub token_account: Account<'info, TokenAccount>,
}
```

---

## Conclusion

Solana security relies on:

1. **Understanding the account model** - Accounts are data, programs are code
2. **Proper authority checks** - Always verify who can do what
3. **Safe arithmetic** - Always use checked operations
4. **Careful CPI** - Validate all external calls thoroughly
5. **Reentrancy awareness** - Update state before external calls
6. **Anchor constraints** - Declare requirements, not imperative checks

Remember: **Security is not about avoiding all risks, it's about understanding risks and making informed decisions.**

---

## Additional Resources

- [Solana Docs - Programs](https://docs.solana.com/developers/programs)
- [Anchor Book - Account Constraints](https://www.anchor-lang.com/docs/accounts)
- [Solana Cookbook - Security](https://solanacookbook.com/security/)
- [Common Solana Vulnerabilities](https://github.com/coral-xyz/spl/security)
- [Runtime Verification Reports](https://github.com/Certora/tutorials)

---

**Disclaimer**: This guide is educational. Real Solana program security requires professional audits and continuous learning.
