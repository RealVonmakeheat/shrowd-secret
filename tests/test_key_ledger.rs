// Integration tests for key_ledger module
use shrowd_secret::key_ledger::{KeyLedger, KeyMetadata, KeyDerivationRequest, KeyType};
use shrowd_secret::secret_config::FastCryptoProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_ledger_creation() {
        let ledger = KeyLedger::new();
        assert!(ledger.is_ok());
    }

    #[test]
    fn test_key_generation() {
        let mut ledger = KeyLedger::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (signing_key, _) = provider.generate_keypair().unwrap();
        
        let metadata = KeyMetadata {
            purpose: "test".to_string(),
            owner: "test_suite".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            tags: vec!["test".to_string()],
        };
        
        let key = ledger.generate_key(
            "test_key", 
            KeyType::Encryption, 
            None, 
            metadata,
            &signing_key
        );
        assert!(key.is_ok());
        
        let public_key = key.unwrap();
        assert_eq!(public_key.0.len(), 32);
    }

    #[test]
    fn test_key_retrieval() {
        let mut ledger = KeyLedger::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (signing_key, _) = provider.generate_keypair().unwrap();
        
        let metadata = KeyMetadata {
            purpose: "test".to_string(),
            owner: "test_suite".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            tags: vec!["test".to_string()],
        };
        
        let _public_key = ledger.generate_key(
            "test_key", 
            KeyType::Encryption, 
            None, 
            metadata,
            &signing_key
        ).unwrap();
        
        let retrieved = ledger.get_key("test_key");
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_key_derivation() {
        let mut ledger = KeyLedger::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (signing_key, _) = provider.generate_keypair().unwrap();
        
        let metadata = KeyMetadata {
            purpose: "parent".to_string(),
            owner: "test_suite".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            tags: vec!["parent".to_string()],
        };
        
        let _parent_key = ledger.generate_key(
            "parent_key", 
            KeyType::Master, 
            None, 
            metadata,
            &signing_key
        ).unwrap();
        
        let derivation_request = KeyDerivationRequest {
            master_key_id: "parent_key".to_string(),
            derivation_path: vec![0, 1, 2],
            purpose: "child_key".to_string(),
            metadata: KeyMetadata {
                purpose: "child".to_string(),
                owner: "test_suite".to_string(),
                permissions: vec!["read".to_string()],
                tags: vec!["child".to_string()],
            },
        };
        
        let derived = ledger.derive_key(&derivation_request, &signing_key);
        assert!(derived.is_ok());
    }

    #[test]
    fn test_key_exists() {
        let mut ledger = KeyLedger::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (signing_key, _) = provider.generate_keypair().unwrap();
        
        let metadata = KeyMetadata {
            purpose: "test".to_string(),
            owner: "test_suite".to_string(),
            permissions: vec!["read".to_string(), "write".to_string()],
            tags: vec!["test".to_string()],
        };
        
        let _key = ledger.generate_key(
            "exist_key", 
            KeyType::Session, 
            None, 
            metadata,
            &signing_key
        ).unwrap();
        
        // Test that the key exists
        let exists = ledger.get_key("exist_key");
        assert!(exists.is_some());
        
        // Test that non-existent key doesn't exist
        let not_exists = ledger.get_key("non_existent");
        assert!(not_exists.is_none());
    }
}
