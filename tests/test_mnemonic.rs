#[cfg(test)]
mod tests {
    use shrowd_secret::secret_config::*;

    #[test]
    fn test_mnemonic_generation() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        
        assert_eq!(mnemonic.get_words().len(), 30);
        
        // Verify all words are in the wordlist
        let validation = generator.validate_mnemonic(&mnemonic).unwrap();
        assert!(validation);
    }

    #[test]
    fn test_mnemonic_key_derivation() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        
        let recovery_data = generator.generate_keys_from_mnemonic(&mnemonic, None).unwrap();
        
        // Verify we get 5 different keys
        assert_ne!(recovery_data.derived_keys.master_key.0, recovery_data.derived_keys.signing_key.0);
        assert_ne!(recovery_data.derived_keys.master_key.0, recovery_data.derived_keys.encryption_key.0);
        assert_ne!(recovery_data.derived_keys.signing_key.0, recovery_data.derived_keys.encryption_key.0);
    }

    #[test]
    fn test_mnemonic_deterministic_recovery() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        
        // Generate keys twice from same mnemonic
        let recovery_data1 = generator.generate_keys_from_mnemonic(&mnemonic, None).unwrap();
        let recovery_data2 = generator.generate_keys_from_mnemonic(&mnemonic, None).unwrap();
        
        // Should be identical
        assert_eq!(recovery_data1.derived_keys.master_key.0, recovery_data2.derived_keys.master_key.0);
        assert_eq!(recovery_data1.derived_keys.signing_key.0, recovery_data2.derived_keys.signing_key.0);
        assert_eq!(recovery_data1.derived_keys.encryption_key.0, recovery_data2.derived_keys.encryption_key.0);
    }

    #[test]
    fn test_keypair_with_mnemonic() {
        let (keypair, mnemonic) = KeyPair::generate_with_mnemonic().unwrap();
        
        // Recover the same keypair
        let recovered_keypair = KeyPair::from_mnemonic(&mnemonic, None).unwrap();
        
        assert_eq!(keypair.private.0, recovered_keypair.private.0);
        assert_eq!(keypair.public.0, recovered_keypair.public.0);
    }

    #[test]
    fn test_mnemonic_from_string() {
        // Use valid words from our wordlist
        let test_phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit";
        
        let mnemonic = MnemonicPhrase::from_string(test_phrase).unwrap();
        assert_eq!(mnemonic.get_words().len(), 30);
        
        let phrase_back = mnemonic.to_string();
        assert_eq!(test_phrase, phrase_back);
    }

    #[test]
    fn test_mnemonic_with_passphrase() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        
        // Generate keys with different passphrases
        let keys_no_pass = generator.generate_keys_from_mnemonic(&mnemonic, None).unwrap();
        let keys_with_pass = generator.generate_keys_from_mnemonic(&mnemonic, Some("test_passphrase")).unwrap();
        
        // Should be different
        assert_ne!(keys_no_pass.derived_keys.master_key.0, keys_with_pass.derived_keys.master_key.0);
    }

    #[test]
    fn test_specialized_keypairs_from_mnemonic() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        
        let master_keypair = KeyPair::from_mnemonic(&mnemonic, None).unwrap();
        let signing_keypair = KeyPair::signing_keypair_from_mnemonic(&mnemonic, None).unwrap();
        let encryption_keypair = KeyPair::encryption_keypair_from_mnemonic(&mnemonic, None).unwrap();
        
        // All should be different
        assert_ne!(master_keypair.private.0, signing_keypair.private.0);
        assert_ne!(master_keypair.private.0, encryption_keypair.private.0);
        assert_ne!(signing_keypair.private.0, encryption_keypair.private.0);
    }

    #[test]
    fn test_recovery_data_export() {
        let generator = MnemonicKeyGenerator::new();
        let mnemonic = generator.generate_mnemonic().unwrap();
        let recovery_data = generator.generate_keys_from_mnemonic(&mnemonic, None).unwrap();
        
        let export = recovery_data.export_recovery_info();
        assert!(export.contains("Crypto Recovery Data"));
        assert!(export.contains(&mnemonic.to_string()));
    }

    #[test]
    fn test_invalid_mnemonic_validation() {
        let generator = MnemonicKeyGenerator::new();
        
        // Too few words
        let short_phrase = MnemonicPhrase::from_string("abandon ability able").unwrap_or_else(|_| {
            MnemonicPhrase { words: vec!["abandon".to_string(), "ability".to_string(), "able".to_string()] }
        });
        assert!(!generator.validate_mnemonic(&short_phrase).unwrap());
        
        // Invalid word
        let invalid_phrase = MnemonicPhrase { 
            words: vec!["invalidword"; 30].iter().map(|s| s.to_string()).collect() 
        };
        assert!(!generator.validate_mnemonic(&invalid_phrase).unwrap());
    }

    #[test]
    fn test_mnemonic_word_access() {
        let test_phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit";
        let mnemonic = MnemonicPhrase::from_string(test_phrase).unwrap();
        
        assert_eq!(mnemonic.get_word(0), Some(&"abandon".to_string()));
        assert_eq!(mnemonic.get_word(1), Some(&"ability".to_string()));
        assert_eq!(mnemonic.get_word(29), Some(&"admit".to_string()));
        assert_eq!(mnemonic.get_word(30), None);
    }
}
