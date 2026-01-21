# Quick Reference Guide

This document provides quick commands and workflows for using the Solana Security Examples.

## Directory Structure

```
solana-security-template/
├── programs/
│   ├── missing_account_validation/      # Lesson 1: Account validation
│   ├── incorrect_authority_check/       # Lesson 2: Authority checks
│   ├── unsafe_arithmetic/               # Lesson 3: Safe arithmetic
│   ├── cpi_misuse/                      # Lesson 4: Safe CPI
│   └── reentrancy_risk/                 # Lesson 5: Reentrancy prevention
├── tests/                               # Integration tests
├── README.md                            # Main documentation
├── BUILD_AND_RUN.md                     # Setup instructions
├── SECURITY_PATTERNS.md                 # Security concepts
└── QUICK_REFERENCE.md                   # This file
```

## Learning Sequence

### Step 1: Setup
```bash
cd solana-security-template
cargo build --release
```

### Step 2: Study Each Vulnerability

For each vulnerability folder:

1. **Read the vulnerability**
   ```bash
   cat programs/VULNERABILITY_NAME/src/vulnerable.rs
   ```

2. **Study the comments**
   - Understand WHAT is broken
   - Understand WHY it's unsafe
   - Understand the SEVERITY

3. **Read the fix**
   ```bash
   cat programs/VULNERABILITY_NAME/src/secure.rs
   ```

4. **Compare the differences**
   - What changed?
   - Why is it safer?
   - What patterns are used?

### Step 3: Deep Dive

For detailed security concepts, read:
```bash
cat SECURITY_PATTERNS.md
```

## Program Descriptions

### 1. Missing Account Validation
**File**: `programs/missing_account_validation/`

**Vulnerability**: Accepting arbitrary accounts without verifying they belong to the expected token mint.

**Learn**: Anchor's `#[account(...)]` constraints and account relationships.

```bash
# View vulnerable version
cat programs/missing_account_validation/src/vulnerable.rs | grep "VULNERABILITY" -A 5

# View secure version
cat programs/missing_account_validation/src/secure.rs | grep "SECURE" -A 5
```

### 2. Incorrect Authority Check
**File**: `programs/incorrect_authority_check/`

**Vulnerability**: Not verifying that the authority is the actual owner of an account.

**Learn**: Proper signer verification and ownership checks.

```bash
cat programs/incorrect_authority_check/src/vulnerable.rs | grep "VULNERABILITY" -A 3
cat programs/incorrect_authority_check/src/secure.rs | grep "SECURE" -A 3
```

### 3. Unsafe Arithmetic
**File**: `programs/unsafe_arithmetic/`

**Vulnerability**: Using unchecked arithmetic that silently overflows/underflows.

**Learn**: Checked arithmetic operations with `checked_add`, `checked_sub`, `checked_mul`.

```bash
cat programs/unsafe_arithmetic/src/vulnerable.rs | grep "wrapping_" 
cat programs/unsafe_arithmetic/src/secure.rs | grep "checked_"
```

### 4. CPI Misuse
**File**: `programs/cpi_misuse/`

**Vulnerability**: Calling other programs without proper validation or error handling.

**Learn**: Safe CPI patterns with account verification and return value checking.

```bash
cat programs/cpi_misuse/src/vulnerable.rs | grep "invoke"
cat programs/cpi_misuse/src/secure.rs | grep "CpiContext"
```

### 5. Reentrancy Risk
**File**: `programs/reentrancy_risk/`

**Vulnerability**: State mutations after external calls, allowing reentrancy attacks.

**Learn**: Checks-Effects-Interactions pattern and reentrancy guards.

```bash
cat programs/reentrancy_risk/src/vulnerable.rs | grep "INTERACTION"
cat programs/reentrancy_risk/src/secure.rs | grep "PHASE"
```

## Common Tasks

### Build All Programs
```bash
cargo build --release
```

### Build Specific Program
```bash
cargo build -p missing_account_validation --release
```

### Run All Tests
```bash
cargo test
```

### Run Tests for Specific Program
```bash
cargo test -p incorrect_authority_check
```

### Run Tests with Output
```bash
cargo test -- --nocapture
```

### Check Code Without Building
```bash
cargo check
```

### Format Code
```bash
cargo fmt
```

### Lint Code
```bash
cargo clippy
```

### View Program Binary Size
```bash
ls -lh target/deploy/*.so
```

### Deploy to Local Network
```bash
# Terminal 1: Start validator
solana-test-validator

# Terminal 2: Deploy program
solana program deploy target/deploy/missing_account_validation.so
```

## Key Concepts to Understand

### 1. Solana Account Model
- Accounts hold data
- Programs are stateless
- Only owner can modify account data
- See `SECURITY_PATTERNS.md` for details

### 2. Signers
- Transactions must be signed
- Signer verification prevents unauthorized access
- Always check `#[account(signer)]`

### 3. Checked Arithmetic
- Use `checked_add()`, `checked_sub()`, `checked_mul()`
- Returns `Option<T>` - handle with `?` operator
- Never use `+`, `-`, `*` for large values

### 4. CPI Safety
- Verify program ID matches expected value
- Check all account relationships
- Handle return values
- Use proper signer delegation

### 5. Reentrancy Prevention
- Update state BEFORE external calls
- Follow Checks-Effects-Interactions pattern
- Use reentrancy guards if needed

## Common Mistakes

| Mistake | Why It's Bad | Fix |
|---------|-------------|-----|
| Not checking signer | Anyone can act as authority | Use `#[account(signer)]` |
| Unchecked arithmetic | Silent overflow/underflow | Use `checked_*` methods |
| Not validating accounts | Arbitrary data manipulation | Use Anchor constraints |
| Ignoring CPI errors | Program state corruption | Handle all `Result` types |
| CPI before state update | Reentrancy attacks | Update state first |

## File Navigation

```bash
# Read specific parts of a file
# Syntax: sed -n 'START,ENDp' FILENAME

# See vulnerabilities in unsafe_arithmetic
sed -n '1,50p' programs/unsafe_arithmetic/src/vulnerable.rs

# See the Account struct
sed -n '/^#\[account\]/,/^}/p' programs/missing_account_validation/src/vulnerable.rs

# See error codes
sed -n '/^#\[error_code\]/,/^}/p' programs/incorrect_authority_check/src/vulnerable.rs
```

## Testing Strategy

When testing Solana programs:

1. **Setup**: Create necessary accounts and initialize state
2. **Execute**: Call the instruction
3. **Verify**: Check state changes or errors
4. **Compare**: Test vulnerable vs secure versions

Example test flow:
```rust
#[test]
fn test_vulnerability() {
    // Setup: Create accounts
    // Execute: Call vulnerable function
    // Verify: Check what went wrong (or what should have failed)
}

#[test]
fn test_secure_fix() {
    // Setup: Create same accounts
    // Execute: Call secure function
    // Verify: Check proper behavior
}
```

## Security Checklist

Before deploying any Solana program:

- [ ] All authority checks implemented
- [ ] All arithmetic operations checked
- [ ] All account constraints specified
- [ ] CPI return values handled
- [ ] State updated before external calls
- [ ] No panics on invalid input
- [ ] Error messages are clear
- [ ] Program has been tested
- [ ] Program has been audited

## Resources

- [README.md](README.md) - Full overview
- [BUILD_AND_RUN.md](BUILD_AND_RUN.md) - Setup instructions
- [SECURITY_PATTERNS.md](SECURITY_PATTERNS.md) - Deep security concepts
- [Anchor Documentation](https://www.anchor-lang.com/)
- [Solana Documentation](https://docs.solana.com/)

## Questions?

For each program, check:
1. The `VULNERABILITY` comment section - explains what's broken
2. The `FIX` comment section - explains what's fixed
3. The specific function comments - detailed explanations
4. SECURITY_PATTERNS.md - conceptual explanations

---

**Happy Learning!** 🚀

Remember: Understanding vulnerabilities is the first step to writing secure code.
