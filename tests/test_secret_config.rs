// Integration tests for secret_config module
use shrowd_secret::secret_config::FastCryptoProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_crypto_provider_creation() {
        let provider = FastCryptoProvider::new();
        assert!(provider.is_ok());
    }

    #[test]
    fn test_keypair_generation() {
        let provider = FastCryptoProvider::new().unwrap();
        let keypair = provider.generate_keypair();
        assert!(keypair.is_ok());
        
        let (private_key, public_key) = keypair.unwrap();
        assert_eq!(private_key.0.len(), 32);
        assert_eq!(public_key.0.len(), 32);
    }

    #[test]
    fn test_hash_functionality() {
        let provider = FastCryptoProvider::new().unwrap();
        let data = b"test data for hashing";
        let hash_result = provider.hash(data);
        assert!(hash_result.is_ok());
        
        let hash = hash_result.unwrap();
        assert_eq!(hash.0.len(), 32); // Blake3 produces 32-byte hashes
    }

    #[test]
    fn test_encryption_decryption() {
        let provider = FastCryptoProvider::new().unwrap();
        let (private_key, public_key) = provider.generate_keypair().unwrap();
        
        let data = b"secret message";
        let encrypted = provider.encrypt(&public_key, data);
        assert!(encrypted.is_ok());
        
        let encrypted_data = encrypted.unwrap();
        let decrypted = provider.decrypt(&private_key, &encrypted_data);
        assert!(decrypted.is_ok());
        
        let decrypted_data = decrypted.unwrap();
        assert_eq!(data, decrypted_data.as_slice());
    }

    #[test]
    fn test_sign_and_verify() {
        let provider = FastCryptoProvider::new().unwrap();
        let (private_key, public_key) = provider.generate_keypair().unwrap();
        
        let data = b"data to sign";
        let signature = provider.sign(&private_key, data);
        assert!(signature.is_ok());
        
        let sig = signature.unwrap();
        let verification = provider.verify(&public_key, data, &sig);
        assert!(verification.is_ok());
        assert!(verification.unwrap());
    }

    #[test]
    fn test_attic_integrity_verification() {
        let provider = FastCryptoProvider::new().unwrap();
        let code = b"smart contract code";
        let hash = provider.hash(code).unwrap();
        
        let integrity_check = provider.verify_attic_integrity(code, &hash);
        assert!(integrity_check.is_ok());
        assert!(integrity_check.unwrap());
    }

    #[test]
    fn test_attic_code_signing() {
        let provider = FastCryptoProvider::new().unwrap();
        let (private_key, public_key) = provider.generate_keypair().unwrap();
        
        let code = b"attic smart contract";
        let signature = provider.sign_attic_code(&private_key, code);
        assert!(signature.is_ok());
        
        let sig = signature.unwrap();
        let verification = provider.verify_attic_signature(&public_key, code, &sig);
        assert!(verification.is_ok());
        assert!(verification.unwrap());
    }
}
