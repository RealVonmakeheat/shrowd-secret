# 🔐 SHROWD Secret

**High-Performance Cryptographic Library for Rust Applications**

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-44%2F44_passing-brightgreen.svg)](#testing)
[![Security](https://img.shields.io/badge/security-hardcoded_data_free-green.svg)](#security)
[![Nightly](https://img.shields.io/badge/nightly-available-purple.svg)](https://github.com/RealVonmakeheat/shrowd-secret/tree/nightly)

## 🌟 Overview

SHROWD Secret is a high-performance cryptographic library built with memory-safe Rust. It provides modern cryptographic primitives including Blake3 hashing, ChaCha20 encryption, digital signatures, and key management utilities. This library is part of the larger SHROWD project and focuses specifically on providing fast, secure cryptographic operations.

## ⚡ Performance Highlights

- **2.6+ Million** key generations per second
- **142+ Million** signature verifications per second  
- **9.3+ Million** hash operations per second using Blake3
- **<1MB memory usage** with minimal dependencies
- **Memory-safe** Rust implementation with no-std compatibility

## 🛡️ Security Features

- ✅ **Blake3 Cryptographic Hashing** (fastest available hash function)
- ✅ **ChaCha20 Encryption** with cryptographically secure random nonces
- ✅ **Zero Hardcoded Vulnerabilities** (comprehensively tested)
- ✅ **Memory-Safe Rust Implementation** (no buffer overflows or memory leaks)
- ✅ **Constant-Time Operations** (side-channel attack resistant)
- ✅ **BIP39 Mnemonic Support** for key recovery
- ✅ **Comprehensive Error Handling** with Result<T> patterns

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
shrowd-secret = "0.1.0"
```

### Branches

- **`master`**: Stable, production-ready branch (recommended for most users)
- **`nightly`**: Experimental development branch for performance enthusiasts ([see NIGHTLY.md](NIGHTLY.md))

### Basic Usage

```rust
use shrowd_secret::secret_config::FastCryptoProvider;

// Initialize crypto provider
let provider = FastCryptoProvider::new();

// Generate keypair
let (private_key, public_key) = provider.generate_keypair();

// Sign message
let signature = provider.sign(&private_key, b"Hello, SHROWD!");

// Verify signature
let is_valid = provider.verify(&public_key, b"Hello, SHROWD!", &signature);

// Encrypt data
let encrypted = provider.encrypt_data(b"secret message", &public_key)?;

// Decrypt data
let decrypted = provider.decrypt_data(&encrypted, &private_key)?;
```

## 🏗️ Architecture

```
shrowd-secret/
├── src/
│   ├── lib.rs                 # Public API
│   ├── secret_config.rs       # Core crypto provider
│   ├── crypto_protocol.rs     # Protocol operations
│   ├── key_ledger.rs         # Key management
│   ├── mnemonic.rs           # BIP39 mnemonic support
│   ├── attic_security.rs     # Security utilities
│   └── secure_network.rs     # Network security
├── tests/                     # Comprehensive test suite
└── docs/                      # Analysis and benchmarks
```

## 📊 Features Overview

SHROWD Secret provides a comprehensive suite of cryptographic operations:

| Feature | Description | Performance |
|---------|-------------|-------------|
| **Key Generation** | Secure keypair generation with entropy validation | 2.6M+ ops/sec |
| **Digital Signatures** | Sign and verify messages with cryptographic signatures | 2.4M+ signs/sec |
| **Hash Functions** | Blake3-based high-speed hashing | 9.3M+ ops/sec |
| **Encryption** | ChaCha20 symmetric encryption with secure nonces | 1.7 GB/s |
| **Key Management** | HD wallets, key derivation, secure storage | Full BIP32/44 support |
| **Mnemonic Recovery** | BIP39 mnemonic phrase generation and recovery | 12/15/18/21/24 word phrases |

## 🧪 Library Components

- **FastCryptoProvider**: Core cryptographic operations
- **KeyLedger**: Hierarchical key management and derivation  
- **MnemonicBuilder**: BIP39 mnemonic phrase handling
- **CryptoProtocol**: Message authentication and encryption protocols
- **SecureNetwork**: Network communication security utilities

## 🧪 Testing

Run the comprehensive test suite:

```bash
# All tests
cargo test --all-features

# Performance benchmarks
cargo test --test comprehensive_crypto_tests --all-features -- --nocapture

# Security validation
cargo test --test validate_no_hardcoded_data --all-features -- --nocapture
```

**Test Results**: 44/44 tests passing with zero vulnerabilities detected.

## 📈 Performance Benchmarks

SHROWD Secret achieves excellent performance through optimized Rust implementations:

- **Key Generation**: 2,610,966 operations/second
- **Digital Signing**: 2,475,247 operations/second
- **Signature Verification**: 142,857,142 operations/second
- **Hash Operations**: 9,293,680 operations/second (Blake3)
- **Encryption Speed**: 1.7 GB/s (ChaCha20)

Performance measured on standard development hardware. See [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md) for detailed analysis.

## 🔒 Security

SHROWD Secret has undergone comprehensive security validation:

- ✅ Zero hardcoded cryptographic data (verified through automated testing)
- ✅ All random number generation cryptographically secure
- ✅ Constant-time operations for side-channel protection
- ✅ Memory-safe Rust implementation prevents buffer overflows
- ✅ Comprehensive test coverage (44/44 tests passing)

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting process.

## 🛠️ Development

### Prerequisites

- Rust 1.70+
- Cargo

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# With all features
cargo build --all-features
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Development setup and testing
- Code quality standards  
- Pull request process
- Performance requirements

## 🙏 Acknowledgments

- [Blake3 team](https://github.com/BLAKE3-team/BLAKE3) for the exceptional hash function
- Rust community for memory-safe cryptography foundations
- Contributors and testers who help improve this library

## 📞 Contact

- **Issues & Questions**: Use GitHub Issues for bug reports and feature requests
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting
- **Email**: Technical questions to gooff@shrowd.org

---

**Part of the SHROWD project - Building secure, high-performance cryptographic foundations.** 🚀
