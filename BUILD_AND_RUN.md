# Build and Run Guide

Complete setup instructions for building and running the Solana Security Examples.

## Prerequisites Installation

### 1. Install Rust

```bash
# On macOS/Linux:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# On Windows:
# Download and run: https://win.rustup.rs/
```

Verify installation:
```bash
rustc --version
cargo --version
```

### 2. Install Solana CLI

```bash
# Recommended: Install specific version for compatibility
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# Add to PATH (macOS/Linux)
export PATH="/home/YOUR_USER/.local/share/solana/install/active_release/bin:$PATH"

# Windows: Follow installer prompts
```

Verify installation:
```bash
solana --version
```

### 3. Install Anchor

```bash
# Install AVM (Anchor Version Manager)
cargo install --git https://github.com/coral-xyz/anchor --tag v0.29.0 avm

# Install Anchor 0.29.0
avm use 0.29.0

# Verify installation
anchor --version
```

### 4. Setup Local Validator (Optional)

```bash
# Start a local Solana validator for testing
solana-test-validator

# In another terminal, set RPC URL to localhost
solana config set --url localhost
```

## Building the Project

### Build All Programs

```bash
cd solana-security-template

# Build all programs in release mode
cargo build --release

# Or in debug mode (slower execution, better for development)
cargo build
```

### Build Specific Program

```bash
# Build only the missing_account_validation program
cargo build -p missing_account_validation --release

# Build only the incorrect_authority_check program
cargo build -p incorrect_authority_check --release
```

### Output Location

Built program binaries are located at:
```
target/deploy/missing_account_validation.so
target/deploy/incorrect_authority_check.so
target/deploy/unsafe_arithmetic.so
target/deploy/cpi_misuse.so
target/deploy/reentrancy_risk.so
```

## Running Tests

### Run All Tests

```bash
cargo test
```

### Run Tests with Output

```bash
# Show println! output
cargo test -- --nocapture
```

### Run Tests for Specific Program

```bash
cargo test -p missing_account_validation

# With output
cargo test -p missing_account_validation -- --nocapture
```

### Run Specific Test

```bash
cargo test test_vulnerable_transfer -- --nocapture
```

## Development Workflow

### 1. Study a Vulnerability

```bash
# Read the vulnerable code
cat programs/missing_account_validation/src/vulnerable.rs

# Read the secure code
cat programs/missing_account_validation/src/secure.rs
```

### 2. Build the Program

```bash
cargo build -p missing_account_validation
```

### 3. Run Related Tests

```bash
cargo test -p missing_account_validation -- --nocapture
```

### 4. Modify and Experiment

Edit files in `programs/*/src/` and rebuild:
```bash
cargo build -p missing_account_validation
cargo test -p missing_account_validation
```

## Deployment to Network

### Deploy to Devnet

```bash
# Set cluster to devnet
solana config set --url devnet

# Get airdrop for fees
solana airdrop 2 <YOUR_WALLET_ADDRESS>

# Deploy program
solana program deploy target/deploy/missing_account_validation.so
```

### Deploy to Localnet (Recommended for Learning)

```bash
# Terminal 1: Start validator
solana-test-validator

# Terminal 2: Deploy
solana program deploy target/deploy/missing_account_validation.so
```

## Troubleshooting

### Build Fails - Rust Version

```bash
# Update Rust to latest stable
rustup update stable

# Use specific version for this project
rustup override set stable
```

### Build Fails - Anchor Version Mismatch

```bash
# Verify Anchor version
anchor --version

# Should be 0.29.0
avm use 0.29.0
```

### Tests Fail - Missing Dependencies

```bash
# Clean and rebuild
cargo clean
cargo build --release
cargo test
```

### Validator Won't Start

```bash
# Kill any existing validators
pkill solana-test-validator

# Clear validator data and restart
rm -rf test-ledger/
solana-test-validator
```

## Project Structure Reference

```
solana-security-template/
├── Cargo.toml                          # Workspace root config
├── README.md                           # Main documentation
├── BUILD_AND_RUN.md                    # This file
├── SECURITY_PATTERNS.md                # Security deep-dive
│
├── programs/                           # All program crates
│   ├── missing_account_validation/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs                  # Module setup
│   │       ├── vulnerable.rs           # ❌ Vulnerable code
│   │       └── secure.rs               # ✅ Secure code
│   │
│   ├── incorrect_authority_check/
│   ├── unsafe_arithmetic/
│   ├── cpi_misuse/
│   └── reentrancy_risk/
│
└── tests/                              # Integration tests (when added)
    └── integration_tests.rs
```

## Common Commands Cheat Sheet

```bash
# Build everything
cargo build --release

# Build specific program
cargo build -p missing_account_validation

# Run all tests
cargo test

# Run tests for program
cargo test -p missing_account_validation

# Show build output
cargo build --release 2>&1 | tee build.log

# Clean build artifacts
cargo clean

# Check code without building
cargo check

# Format code
cargo fmt

# Lint code
cargo clippy

# View program size
ls -lh target/deploy/*.so
```

## Next Steps

1. ✅ **Install all prerequisites** (Rust, Solana, Anchor)
2. ✅ **Build the project**: `cargo build --release`
3. ✅ **Run tests**: `cargo test`
4. 📖 **Read SECURITY_PATTERNS.md** for deep concepts
5. 🔍 **Study vulnerability folders** (vulnerable.rs → secure.rs)
6. ⚙️ **Experiment** - Modify code and see what breaks
7. 🧪 **Run tests** after changes to validate understanding

## Support

For detailed security concepts, see [SECURITY_PATTERNS.md](SECURITY_PATTERNS.md)

For specific vulnerability details, read the comments in:
- `programs/*/src/vulnerable.rs`
- `programs/*/src/secure.rs`
