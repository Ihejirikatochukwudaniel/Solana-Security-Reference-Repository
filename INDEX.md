# Solana Security Examples - Complete Index

Welcome to the Solana Security Reference Repository! This file helps you navigate the entire project.

## 📚 Documentation Files

### Start Here
1. **[README.md](README.md)** - Project overview and quick start (5 min read)
2. **[BUILD_AND_RUN.md](BUILD_AND_RUN.md)** - Complete setup and build instructions (10 min read)
3. **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick command reference (5 min read)

### Deep Learning
4. **[WALKTHROUGH.md](WALKTHROUGH.md)** - Guided walkthrough of each vulnerability (60 min read)
5. **[SECURITY_PATTERNS.md](SECURITY_PATTERNS.md)** - Comprehensive security patterns guide (90 min read)

### This File
6. **[INDEX.md](INDEX.md)** - Navigation guide (this file)

## 🎯 Learning Path

### Day 1: Setup & Overview (30 minutes)
```
1. Read: README.md
2. Read: BUILD_AND_RUN.md
3. Run:  cargo build --release
4. Verify: All programs build without errors
```

### Day 2-3: Study Each Vulnerability (2-3 hours)

For each of these 5 vulnerabilities, follow this pattern:

```
1. Read: QUICK_REFERENCE.md section for that vulnerability
2. Read: vulnerable.rs file
3. Understand: The VULNERABILITY comments explaining the issue
4. Read: secure.rs file
5. Compare: The differences between versions
6. Read: Relevant section in SECURITY_PATTERNS.md
```

### Day 4: Deep Dive & Experimentation (2+ hours)

```
1. Read: WALKTHROUGH.md - Full walkthrough with explanations
2. Read: SECURITY_PATTERNS.md - All security concepts
3. Modify: Change vulnerable code to experiment
4. Build: `cargo build` to see if your changes work
5. Learn: Understand why changes work or fail
```

### Week 2+: Apply to Your Projects

```
1. Use these patterns in your own Solana programs
2. Run security checklist before deployment
3. Reference this repo when uncertain
4. Share with other developers
```

## 📁 Project Structure

```
solana-security-template/
├── README.md                           # Start here - Overview
├── BUILD_AND_RUN.md                    # How to setup and build
├── QUICK_REFERENCE.md                  # Command reference
├── WALKTHROUGH.md                      # Guided learning path
├── SECURITY_PATTERNS.md                # Deep security guide
├── INDEX.md                            # This file
├── .gitignore                          # Git configuration
├── Cargo.toml                          # Workspace config
│
├── programs/                           # 5 vulnerable programs
│   ├── missing_account_validation/     # Lesson 1 - Account validation
│   ├── incorrect_authority_check/      # Lesson 2 - Authority checks
│   ├── unsafe_arithmetic/              # Lesson 3 - Safe arithmetic
│   ├── cpi_misuse/                     # Lesson 4 - Safe CPI
│   └── reentrancy_risk/                # Lesson 5 - Reentrancy prevention
│
└── tests/                              # Integration tests
    └── integration_tests.rs
```

## 🔒 The 5 Vulnerabilities

### 1. Missing Account Validation
- **File**: `programs/missing_account_validation/`
- **Problem**: Not validating account relationships
- **Fix**: Use Anchor's `#[account(...)]` constraints
- **Time**: 15-20 minutes
- **Key Concept**: Account validation constraints

### 2. Incorrect Authority Check
- **File**: `programs/incorrect_authority_check/`
- **Problem**: Not checking if signer is the owner
- **Fix**: Explicit ownership verification
- **Time**: 15-20 minutes
- **Key Concept**: Signer vs. Owner

### 3. Unsafe Arithmetic
- **File**: `programs/unsafe_arithmetic/`
- **Problem**: Unchecked overflow/underflow
- **Fix**: Use `checked_*` methods
- **Time**: 15-20 minutes
- **Key Concept**: Checked arithmetic

### 4. CPI Misuse
- **File**: `programs/cpi_misuse/`
- **Problem**: Calling other programs unsafely
- **Fix**: Verify IDs, use helpers, handle errors
- **Time**: 20-25 minutes
- **Key Concept**: Safe cross-program invocation

### 5. Reentrancy Risk
- **File**: `programs/reentrancy_risk/`
- **Problem**: State mutations after external calls
- **Fix**: Checks-Effects-Interactions pattern
- **Time**: 20-25 minutes
- **Key Concept**: Reentrancy prevention

## 🚀 Quick Commands

### Build
```bash
cargo build --release                    # Build all programs
cargo build -p PROGRAM_NAME              # Build specific program
```

### Test
```bash
cargo test                               # Run all tests
cargo test -p PROGRAM_NAME               # Test specific program
cargo test -- --nocapture               # Show test output
```

### Deploy
```bash
solana-test-validator                    # Start local validator
solana program deploy target/deploy/*.so # Deploy programs
```

### Code Quality
```bash
cargo fmt                                # Format code
cargo clippy                             # Lint code
cargo check                              # Check without building
```

## 📖 Documentation Map

### For Beginners
- Start: [README.md](README.md)
- Then: [BUILD_AND_RUN.md](BUILD_AND_RUN.md)
- Then: [WALKTHROUGH.md](WALKTHROUGH.md)

### For Experienced Devs
- Start: [QUICK_REFERENCE.md](QUICK_REFERENCE.md)
- Then: [SECURITY_PATTERNS.md](SECURITY_PATTERNS.md)
- Jump to specific programs as needed

### For Questions
- Setup issues: See [BUILD_AND_RUN.md](BUILD_AND_RUN.md#troubleshooting)
- Concept questions: See [SECURITY_PATTERNS.md](SECURITY_PATTERNS.md)
- Detailed explanations: See [WALKTHROUGH.md](WALKTHROUGH.md)
- Command reference: See [QUICK_REFERENCE.md](QUICK_REFERENCE.md)

## 🎓 Learning Objectives

### After Module 1 (Missing Account Validation)
- [ ] Understand Anchor's account constraints
- [ ] Know the difference between `AccountInfo` and `Account<'info, T>`
- [ ] Can write proper `#[derive(Accounts)]` structs

### After Module 2 (Incorrect Authority Check)
- [ ] Understand signers vs. owners
- [ ] Know how to verify ownership
- [ ] Can implement proper permission checks

### After Module 3 (Unsafe Arithmetic)
- [ ] Understand overflow and underflow
- [ ] Know checked arithmetic methods
- [ ] Can prevent arithmetic vulnerabilities

### After Module 4 (CPI Misuse)
- [ ] Understand cross-program invocation
- [ ] Know how to verify external programs
- [ ] Can handle CPI errors properly

### After Module 5 (Reentrancy Risk)
- [ ] Understand Solana's call stack
- [ ] Know Checks-Effects-Interactions pattern
- [ ] Can prevent reentrancy attacks

## ✅ Security Checklist

Before deploying any Solana program:

### Accounts
- [ ] All accounts have proper constraints
- [ ] Account types are correct
- [ ] Relationships between accounts verified

### Authority
- [ ] All signers marked with `#[account(signer)]`
- [ ] Ownership verified where needed
- [ ] Permissions are explicit

### Arithmetic
- [ ] All `+` replaced with `checked_add()`
- [ ] All `-` replaced with `checked_sub()`
- [ ] All `*` replaced with `checked_mul()`
- [ ] Division checked for zero

### CPI
- [ ] Program IDs verified
- [ ] Account relationships validated
- [ ] Return values handled
- [ ] Signers delegated correctly

### Reentrancy
- [ ] State updated before external calls
- [ ] Follows Checks-Effects-Interactions
- [ ] No reentrancy windows

### General
- [ ] No `panic!()` or `unwrap()` calls
- [ ] All errors handled
- [ ] Code reviewed by someone else
- [ ] Program tested thoroughly
- [ ] Program professionally audited

## 📚 External Resources

### Official Documentation
- [Solana Documentation](https://docs.solana.com/)
- [Anchor Book](https://www.anchor-lang.com/)
- [Solana Cookbook](https://solanacookbook.com/)

### Security
- [Solana Program Library Docs](https://github.com/solana-labs/solana-program-library)
- [Common Solana Vulnerabilities](https://github.com/coral-xyz/spl/security)
- [Runtime Verification Reports](https://github.com/Certora)

### Community
- [Solana Dev Community Discord](https://discord.gg/solana)
- [Anchor GitHub Discussions](https://github.com/coral-xyz/anchor/discussions)

## 🤝 Contributing

Found an issue or want to improve the examples?
- Open an issue to report problems
- Submit pull requests to fix or improve content
- Share suggestions for new vulnerabilities to cover

## 📝 License

This educational repository is provided as-is. Use the patterns and concepts in your own projects.

## ⚠️ Disclaimer

**DO NOT USE THE VULNERABLE CODE IN PRODUCTION**

These examples are deliberately flawed for educational purposes. Always:
1. Have your programs professionally audited
2. Test thoroughly before deployment
3. Follow security best practices
4. Stay updated on new vulnerabilities

---

## 🎯 Next Steps

1. **Start Learning**:
   ```bash
   cd solana-security-template
   cat README.md
   ```

2. **Setup Your Environment**:
   ```bash
   cargo build --release
   ```

3. **Study Vulnerabilities**:
   ```bash
   cat programs/missing_account_validation/src/vulnerable.rs
   cat programs/missing_account_validation/src/secure.rs
   ```

4. **Read Deep Concepts**:
   ```bash
   cat SECURITY_PATTERNS.md
   ```

5. **Apply to Your Code**:
   - Use patterns in your own programs
   - Reference this repo when uncertain

---

**Welcome to Solana Security Learning! 🚀**

Start with [README.md](README.md) or [BUILD_AND_RUN.md](BUILD_AND_RUN.md)
