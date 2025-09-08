# Contributing to SHROWD Secret

Thank you for your interest in contributing to SHROWD Secret! This project aims to provide the fastest, most secure cryptographic foundation for blockchain applications.

## 🚀 Project Vision

SHROWD Secret is designed to outperform major blockchain encryption layers (Bitcoin, Ethereum, Solana) by 232x to 71,428x while maintaining production-grade security with zero hardcoded vulnerabilities.

## 🛠️ Development Setup

### Prerequisites
- Rust 1.70+
- Git

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/shrowd-secret.git
cd shrowd-secret
cargo build --all-features
cargo test --all-features
```

## 🧪 Testing

All contributions must pass our comprehensive test suite:

```bash
# Run all tests
cargo test --all-features

# Run performance benchmarks
cargo test --test comprehensive_crypto_tests --all-features -- --nocapture

# Run security validation
cargo test --test validate_no_hardcoded_data --all-features -- --nocapture
```

**Test Requirements:**
- All existing tests must pass
- New features must include tests
- Performance regressions are not acceptable
- Security tests must validate no hardcoded data

## 📋 Contribution Guidelines

### Code Quality Standards
- **Memory Safety**: All code must be memory-safe Rust
- **Performance**: Maintain industry-leading performance benchmarks
- **Security**: Zero hardcoded cryptographic data
- **Documentation**: All public APIs must be documented
- **Testing**: 100% test coverage for critical paths

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-improvement`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Update documentation if needed
7. Commit with descriptive messages
8. Push to your fork
9. Create a Pull Request

### Commit Message Format
```
🎯 Type: Brief description

Detailed explanation of changes
- What was changed
- Why it was changed  
- Any performance impacts

Fixes #issue_number
```

**Types:**
- 🚀 `feat`: New features
- 🐛 `fix`: Bug fixes
- ⚡ `perf`: Performance improvements
- 🛡️ `security`: Security enhancements
- 📚 `docs`: Documentation updates
- 🧪 `test`: Test additions/improvements
- 🔧 `refactor`: Code refactoring

## 🔐 Security Contributions

Security is paramount for SHROWD Secret. If you find a security vulnerability:

1. **DO NOT** open a public issue
2. Email security reports to: gooff@shrowd.org
3. Include detailed reproduction steps
4. Allow time for assessment and fix before public disclosure

## 📊 Performance Standards

All contributions must maintain our performance advantages:

- Key Generation: >2.5M operations/second
- Digital Signing: >2.4M operations/second  
- Signature Verification: >140M operations/second
- Hash Operations: >9M operations/second

## 🏆 Recognition

Contributors will be recognized in:
- CHANGELOG.md for their contributions
- README.md contributors section
- Release notes for significant improvements

## 📞 Getting Help

- **Issues**: Create GitHub issues for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Email**: Technical questions to gooff@shrowd.org

## 📄 License

By contributing to SHROWD Secret, you agree that your contributions will be licensed under the MIT License.

---

**Together, we're building the cryptographic foundation for next-generation blockchain applications!** 🚀
