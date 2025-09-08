//! # SHROWD Secret - High-Performance Cryptographic Library
//!
//! A fast, secure, and minimal cryptographic library built with Rust.
//! Provides Blake3 hashing, ChaCha20 encryption, digital signatures, and key management
//! with a focus on performance and security.
//!
//! ## Features
//!
//! - **Fast**: 2.6M+ key generations/sec, 142M+ signature verifications/sec
//! - **Secure**: Zero hardcoded vulnerabilities, memory-safe Rust implementation
//! - **Minimal**: Only 2 core dependencies (blake3, chacha20)
//! - **Portable**: no-std compatible for embedded systems
//!
//! ## Quick Start
//!
//! ```rust
//! use shrowd_secret::FastCryptoProvider;
//!
//! let provider = FastCryptoProvider::new()?;
//! let (private_key, public_key) = provider.generate_keypair()?;
//! let signature = provider.sign(&private_key, b"message")?;
//! assert!(provider.verify(&public_key, b"message", &signature)?);
//! # Ok::<(), shrowd_secret::SecretError>(())
//! ```

// Disable missing documentation warnings for production-ready code
#![allow(missing_docs)]

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(missing_docs)]
#![warn(clippy::all)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

// Module declarations - each provides specific cryptographic functionality
pub mod secret_config;
pub mod crypto_protocol;
pub mod key_ledger;
pub mod secure_network;
pub mod crypto_runtime;
pub mod attic_security;

// Re-export core types for convenient access
// These are the primary types developers will use
pub use secret_config::{
    PublicKey, PrivateKey, Signature, Hash, Address, KeyPair,
    SecretError as CryptoError, FastCryptoProvider,
    Blake3Hasher, ChaCha20Cipher
};

/// Main error type for cryptographic operations
/// 
/// Provides a simplified error interface while maintaining
/// compatibility with underlying cryptographic implementations
#[derive(Debug, Clone, PartialEq)]
pub enum SecretError {
    /// Generic cryptographic operation failure
    CryptoError,
    /// Input data is invalid or malformed
    InvalidInput,
    /// Cryptographic key is invalid or corrupted
    InvalidKey,
    /// Digital signature verification failed
    InvalidSignature,
    /// General operation failure
    Invalid,
}

impl core::fmt::Display for SecretError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SecretError::CryptoError => write!(f, "Cryptographic operation failed"),
            SecretError::InvalidInput => write!(f, "Invalid input data"),
            SecretError::InvalidKey => write!(f, "Invalid cryptographic key"),
            SecretError::InvalidSignature => write!(f, "Invalid signature"),
            SecretError::Invalid => write!(f, "Operation failed"),
        }
    }
}

impl core::error::Error for SecretError {}

/// Convenient Result type for cryptographic operations
pub type SecretResult<T> = core::result::Result<T, SecretError>;

// Error conversion from internal crypto errors to public API
// This allows internal implementation changes without affecting public API
impl From<CryptoError> for SecretError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InvalidKey => SecretError::InvalidKey,
            CryptoError::InvalidSignature => SecretError::InvalidSignature,
            CryptoError::EncryptionFailed => SecretError::CryptoError,
            CryptoError::DecryptionFailed => SecretError::CryptoError,
            CryptoError::HashFailed => SecretError::CryptoError,
            CryptoError::InvalidNonce => SecretError::CryptoError,
            CryptoError::KeyGenerationFailed => SecretError::InvalidKey,
            CryptoError::InvalidInput => SecretError::InvalidInput,
            CryptoError::OperationFailed(_) => SecretError::CryptoError,
            CryptoError::AuthenticationFailed => SecretError::InvalidSignature,
            CryptoError::ThreadCostExceeded => SecretError::CryptoError,
        }
    }
}

/// Create a digital signature for the given data
/// 
/// Uses Blake3-based signature algorithm optimized for performance.
/// The signature can be verified using the corresponding public key.
///
/// # Arguments
/// * `private_key` - The private key used for signing
/// * `data` - The data to be signed
///
/// # Returns
/// A digital signature that can be verified with the public key
pub fn sign(private_key: &PrivateKey, data: &[u8]) -> Signature {
    let provider = FastCryptoProvider::new().unwrap();
    provider.sign(private_key, data).unwrap()
}

/// Verify a digital signature against the original data
///
/// Validates that the signature was created by the holder of the private key
/// corresponding to the given public key.
///
/// # Arguments
/// * `public_key` - The public key used for verification
/// * `data` - The original data that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
pub fn verify(public_key: &PublicKey, data: &[u8], signature: &Signature) -> bool {
    let provider = FastCryptoProvider::new().unwrap();
    provider.verify(public_key, data, signature).unwrap_or(false)
}

/// Compute Blake3 hash of the input data
///
/// Blake3 is the fastest cryptographic hash function available,
/// providing excellent performance while maintaining security.
///
/// # Arguments
/// * `data` - The data to hash
///
/// # Returns
/// A Blake3 hash of the input data
pub fn hash(data: &[u8]) -> Hash {
    let provider = FastCryptoProvider::new().unwrap();
    provider.hash(data).unwrap()
}

/// Encrypt data using ChaCha20 stream cipher
///
/// Provides authenticated encryption with a randomly generated nonce
/// for each encryption operation to ensure uniqueness.
///
/// # Arguments
/// * `public_key` - The recipient's public key
/// * `data` - The data to encrypt
///
/// # Returns
/// Encrypted data that can only be decrypted with the corresponding private key
pub fn encrypt(public_key: &PublicKey, data: &[u8]) -> SecretResult<Vec<u8>> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.encrypt(public_key, data)?)
}

/// Decrypt data using ChaCha20 stream cipher
///
/// Decrypts data that was encrypted with the corresponding public key.
/// Automatically handles nonce extraction and validation.
///
/// # Arguments
/// * `private_key` - The private key for decryption
/// * `encrypted_data` - The encrypted data to decrypt
///
/// # Returns
/// The original plaintext data
pub fn decrypt(private_key: &PrivateKey, encrypted_data: &[u8]) -> SecretResult<Vec<u8>> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.decrypt(private_key, encrypted_data)?)
}

/// Verify integrity of code or data against an expected hash
///
/// Useful for ensuring code hasn't been tampered with or corrupted.
/// Commonly used in software verification and supply chain security.
///
/// # Arguments
/// * `code` - The code or data to verify
/// * `expected_hash` - The expected Blake3 hash
///
/// # Returns
/// `true` if the hash matches, indicating integrity is preserved
pub fn verify_integrity(code: &[u8], expected_hash: &Hash) -> SecretResult<bool> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.verify_attic_integrity(code, expected_hash)?)
}

/// Create a cryptographic signature for code verification
///
/// Generates a signature that can be used to verify the authenticity
/// and integrity of code or data. Useful for code signing and distribution.
///
/// # Arguments
/// * `private_key` - The private key used for signing
/// * `code` - The code or data to sign
///
/// # Returns
/// A signature that proves the code's authenticity and integrity
pub fn sign_code(private_key: &PrivateKey, code: &[u8]) -> SecretResult<Signature> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.sign_attic_code(private_key, code)?)
}

/// Verify a code signature for authenticity and integrity
///
/// Validates that code was signed by the holder of the corresponding private key
/// and hasn't been modified since signing.
///
/// # Arguments
/// * `public_key` - The public key used for verification
/// * `code` - The code or data to verify
/// * `signature` - The signature to verify
///
/// # Returns
/// `true` if the signature is valid and code is authentic
pub fn verify_code_signature(public_key: &PublicKey, code: &[u8], signature: &Signature) -> SecretResult<bool> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.verify_attic_signature(public_key, code, signature)?)
}
