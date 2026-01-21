# Solana Security Reference Repository

A comprehensive educational repository demonstrating common Solana program vulnerabilities and their secure implementations. This project is designed for developers learning Solana security best practices.

## Overview

This repository contains deliberately vulnerable Solana programs alongside their secure counterparts, helping developers understand:
- Why certain patterns are dangerous
- How to identify security issues in code
- Best practices for writing secure Solana programs
- Common attack vectors and mitigations

**⚠️ WARNING**: The code in `vulnerable.rs` files should **NEVER** be used in production. These are educational examples only.

## Repository Structure

```
solana-security-template/
├── programs/
│   ├── missing_account_validation/     # Not validating account relationships
│   ├── incorrect_authority_check/      # Weak or missing permission checks
│   ├── unsafe_arithmetic/              # Integer overflow/underflow vulnerabilities
│   ├── cpi_misuse/                     # Cross-program invocation mistakes
│   └── reentrancy_risk/                # Reentrancy and state mutation issues
├── tests/                              # Test scripts demonstrating vulnerabilities
├── Cargo.toml                          # Workspace configuration
├── README.md                           # This file
├── SECURITY_PATTERNS.md                # In-depth security guide
└── BUILD_AND_RUN.md                    # Setup and execution instructions
```

## Vulnerabilities Covered

### 1. **Missing Account Validation**
- **Problem**: Not validating that accounts belong to expected mints or programs
- **Risk**: Arbitrary data manipulation, token theft, state corruption
- **Location**: `programs/missing_account_validation/`
- **Learning Goal**: Understand Anchor's `#[account(...)]` constraints

### 2. **Incorrect Authority Check**
- **Problem**: Weak or missing permission verification
- **Risk**: Unauthorized state changes, account takeover
- **Location**: `programs/incorrect_authority_check/`
- **Learning Goal**: Implement proper signer validation and ownership checks

### 3. **Unsafe Arithmetic**
- **Problem**: Integer overflow/underflow in calculations
- **Risk**: Fund loss, state inconsistency, unexpected behavior
- **Location**: `programs/unsafe_arithmetic/`
- **Learning Goal**: Use checked arithmetic operations

### 4. **CPI Misuse**
- **Problem**: Incorrect cross-program invocations (missing account validation, wrong signers)
- **Risk**: Program state corruption, fund loss
- **Location**: `programs/cpi_misuse/`
- **Learning Goal**: Safe CPI patterns and account passing

### 5. **Reentrancy Risk**
- **Problem**: State mutations that can be re-entered before completion
- **Risk**: Double spending, fund theft
- **Location**: `programs/reentrancy_risk/`
- **Learning Goal**: Understand Solana's call-stack model and reentrancy defenses

## File Organization

Each vulnerability folder contains:

```
programs/vulnerability_name/
├── Cargo.toml                  # Program dependencies
└── src/
    ├── lib.rs                  # Module exports
    ├── mod.rs                  # Module declarations
    ├── vulnerable.rs           # ❌ Insecure example with detailed comments
    └── secure.rs               # ✅ Fixed version with explanations
```

## Quick Start

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor --tag v0.29.0 avm
avm use 0.29.0
```

### Building All Programs

```bash
cd solana-security-template

# Build all programs
cargo build --release

# Or build a specific program
cargo build -p missing_account_validation --release
```

### Running Tests

```bash
# Run all tests
cargo test

# Run tests for a specific program
cargo test -p missing_account_validation
```

### Viewing the Code

Each program has:
1. **vulnerable.rs** - Read this first to understand the vulnerability
2. **secure.rs** - Then read this to see the fix

Example flow:
```bash
# Study the vulnerable version
cat programs/missing_account_validation/src/vulnerable.rs

# Compare with the secure version
cat programs/missing_account_validation/src/secure.rs

# Read the detailed patterns document
cat SECURITY_PATTERNS.md
```

## Learning Path

1. **Start with README.md** (this file) - Get an overview
2. **Read SECURITY_PATTERNS.md** - Understand Solana's account model and security concepts
3. **For each vulnerability**:
   - Read `vulnerable.rs` - Understand what's broken
   - Read `secure.rs` - Learn the fix
   - Review comments explaining the issues
4. **Run tests** - See the vulnerabilities in action
5. **Modify examples** - Experiment and break/fix code

## Key Concepts

### Solana Account Model
- Every account has an owner
- Data is mutable only if you own the account
- Programs are stateless; data lives in accounts
- Read the deep-dive in `SECURITY_PATTERNS.md`

### Anchor Framework
- Provides macros for account validation
- `#[account(...)]` constraints prevent common errors
- Still requires security awareness from developers

### Authority Patterns
- Verify signers using `Signer<'info>` type
- Check account ownership when needed
- Implement explicit permission models

## Common Mistakes to Watch For

| Issue | Impact | Prevention |
|-------|--------|-----------|
| Missing account checks | Arbitrary data manipulation | Use Anchor constraints |
| Weak signer validation | Unauthorized access | Always check signers |
| Unchecked arithmetic | Fund loss / overflow | Use checked operations |
| Invalid CPI setup | Program state corruption | Validate all CPI accounts |
| State mutations before returns | Reentrancy attacks | Understand call stack |

## Recommended Reading

- [Solana Program Library Documentation](https://docs.solana.com/developers/programs)
- [Anchor Book](https://www.anchor-lang.com/)
- [Solana Security Workshop](https://github.com/solana-labs/solana-security-txt)
- [Runtime Verification Security Audit Reports](https://github.com/Certora)

## Contributing

This is an educational project. Suggestions for improvements, additional vulnerabilities, or corrections are welcome!

## Disclaimer

**This repository contains deliberately vulnerable code for educational purposes only.** 

- Do NOT use `vulnerable.rs` code in production
- These examples are simplified for teaching
- Real audits require professional security reviews
- Always have programs audited by security specialists

## License

MIT License - See LICENSE file for details

## Contact & Support

For questions about specific vulnerabilities or to suggest additions, please open an issue or discussion.

---

**Happy learning! Remember: Understanding security vulnerabilities is the first step to writing secure code.**
