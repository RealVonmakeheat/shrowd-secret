// SHROWD Secret v0.1.0 - Fast Cryptographic Operations
// Only dependencies: blake3, chacha20

// Module declarations
pub mod secret_config;
pub mod crypto_protocol;
pub mod key_ledger;
pub mod secure_network;
pub mod crypto_runtime;
pub mod attic_security;

// Re-export core crypto types from secret_config
pub use secret_config::{
    PublicKey, PrivateKey, Signature, Hash, Address, KeyPair,
    SecretError as ConfigSecretError, FastCryptoProvider,
    Blake3Hasher, ChaCha20Cipher
};

// Common error/result
#[derive(Debug, Clone)]
pub enum SecretError {
    CryptoError,
    InvalidInput,
    InvalidKey,
    InvalidSignature,
    Invalid,
}

pub type SecretResult<T> = core::result::Result<T, SecretError>;

// Add error conversion implementations
impl From<ConfigSecretError> for SecretError {
    fn from(err: ConfigSecretError) -> Self {
        match err {
            ConfigSecretError::InvalidKey => SecretError::InvalidKey,
            ConfigSecretError::InvalidSignature => SecretError::InvalidSignature,
            ConfigSecretError::EncryptionFailed => SecretError::CryptoError,
            ConfigSecretError::DecryptionFailed => SecretError::CryptoError,
            ConfigSecretError::HashFailed => SecretError::CryptoError,
            ConfigSecretError::InvalidNonce => SecretError::CryptoError,
            ConfigSecretError::KeyGenerationFailed => SecretError::InvalidKey,
            ConfigSecretError::InvalidInput => SecretError::InvalidInput,
            ConfigSecretError::OperationFailed(_) => SecretError::CryptoError,
            ConfigSecretError::AuthenticationFailed => SecretError::InvalidSignature,
            ConfigSecretError::ThreadCostExceeded => SecretError::CryptoError,
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretError::CryptoError => write!(f, "Cryptographic operation failed"),
            SecretError::InvalidInput => write!(f, "Invalid input provided"),
            SecretError::InvalidKey => write!(f, "Invalid cryptographic key"),
            SecretError::InvalidSignature => write!(f, "Invalid signature"),
            SecretError::Invalid => write!(f, "Invalid operation"),
        }
    }
}

// Crypto operations using FastCryptoProvider
pub fn sign(private_key: &PrivateKey, data: &[u8]) -> Signature {
    let provider = FastCryptoProvider::new().unwrap();
    provider.sign(private_key, data).unwrap()
}

pub fn verify(public_key: &PublicKey, data: &[u8], signature: &Signature) -> bool {
    let provider = FastCryptoProvider::new().unwrap();
    provider.verify(public_key, data, signature).unwrap_or(false)
}

pub fn hash(data: &[u8]) -> Hash {
    let provider = FastCryptoProvider::new().unwrap();
    provider.hash(data).unwrap()
}

pub fn encrypt(public_key: &PublicKey, data: &[u8]) -> SecretResult<Vec<u8>> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.encrypt(public_key, data)?)
}

pub fn decrypt(private_key: &PrivateKey, encrypted_data: &[u8]) -> SecretResult<Vec<u8>> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.decrypt(private_key, encrypted_data)?)
}

// Attic repository integrity functions
pub fn verify_attic_integrity(code: &[u8], expected_hash: &Hash) -> SecretResult<bool> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.verify_attic_integrity(code, expected_hash)?)
}

pub fn sign_attic_code(private_key: &PrivateKey, code: &[u8]) -> SecretResult<Signature> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.sign_attic_code(private_key, code)?)
}

pub fn verify_attic_signature(public_key: &PublicKey, code: &[u8], signature: &Signature) -> SecretResult<bool> {
    let provider = FastCryptoProvider::new()?;
    Ok(provider.verify_attic_signature(public_key, code, signature)?)
}
