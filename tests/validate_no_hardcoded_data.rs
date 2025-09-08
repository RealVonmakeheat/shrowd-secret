//! Comprehensive validation tests to prove no hardcoded data remains
//! 
//! These tests specifically validate that all cryptographic operations
//! produce unique, non-hardcoded results every time they run.

use shrowd_secret::*;

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_crypto_provider_no_hardcoded_keys() {
        println!("🔍 Testing FastCryptoProvider for hardcoded key patterns...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        
        // Generate multiple keypairs and ensure they're all different
        let mut keypairs = Vec::new();
        for i in 0..5 {
            let keypair = provider.generate_keypair().expect("Failed to generate keypair");
            println!("Keypair {}: private={}, public={}", 
                i, hex::encode(&keypair.0.0[..8]), hex::encode(&keypair.1.0[..8]));
            keypairs.push(keypair);
        }
        
        // Verify no two keypairs are identical (would indicate hardcoded data)
        for i in 0..keypairs.len() {
            for j in i+1..keypairs.len() {
                assert_ne!(keypairs[i].0.0, keypairs[j].0.0, "Found duplicate private keys - indicates hardcoded data!");
                assert_ne!(keypairs[i].1.0, keypairs[j].1.0, "Found duplicate public keys - indicates hardcoded data!");
            }
        }
        
        println!("✅ All keypairs are unique - no hardcoded key patterns detected");
    }

    #[test]
    fn test_signatures_are_unique() {
        println!("🔍 Testing that signatures are unique for different messages...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        let (private_key, _) = provider.generate_keypair().expect("Failed to generate keypair");
        
        // Generate signatures for different messages
        let mut signatures = Vec::new();
        let messages = [&b"message1"[..], &b"message2"[..], &b"message3"[..], &b"different_msg"[..], &b"test_data"[..]];
        
        for (i, message) in messages.iter().enumerate() {
            let hash = provider.hash(message).expect("Failed to hash message");
            let signature = provider.sign(&private_key, &hash.0).expect("Failed to sign");
            println!("Signature {}: {}", i, hex::encode(&signature.0[..8]));
            signatures.push(signature);
        }
        
        // Verify all signatures are different
        for i in 0..signatures.len() {
            for j in i+1..signatures.len() {
                assert_ne!(signatures[i].0, signatures[j].0, "Found duplicate signatures!");
                assert_ne!(signatures[i].0, [0u8; 64], "Signature should not be all zeros!");
            }
        }
        
        println!("✅ All signatures are unique - no hardcoded signatures detected");
    }

    #[test]
    fn test_hashes_are_deterministic_but_unique() {
        println!("🔍 Testing hash function for proper behavior...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        
        // Same input should produce same hash (deterministic)
        let hash1a = provider.hash(b"test_input").expect("Failed to hash");
        let hash1b = provider.hash(b"test_input").expect("Failed to hash");
        assert_eq!(hash1a.0, hash1b.0, "Same input should produce same hash");
        
        // Different inputs should produce different hashes
        let hash2 = provider.hash(b"different_input").expect("Failed to hash");
        assert_ne!(hash1a.0, hash2.0, "Different inputs should produce different hashes");
        
        // Hash should not be all zeros or other hardcoded patterns
        assert_ne!(hash1a.0, [0u8; 32], "Hash should not be all zeros");
        assert_ne!(hash1a.0, [0xFF; 32], "Hash should not be all ones");
        
        println!("✅ Hash function works correctly - deterministic but unique");
        println!("   Hash of 'test_input': {}", hex::encode(&hash1a.0[..8]));
        println!("   Hash of 'different_input': {}", hex::encode(&hash2.0[..8]));
    }

    #[test]
    fn test_encryption_decryption_no_hardcoded_data() {
        println!("🔍 Testing encryption/decryption for unique outputs...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        let (private_key, public_key) = provider.generate_keypair().expect("Failed to generate keypair");
        
        // Encrypt the same message multiple times - should produce different outputs due to nonce
        let message = b"secret_message_to_encrypt";
        let mut encrypted_outputs = Vec::new();
        
        for i in 0..3 {
            let encrypted = provider.encrypt(&public_key, message).expect("Failed to encrypt");
            println!("Encrypted output {}: {}", i, hex::encode(&encrypted[..8]));
            encrypted_outputs.push(encrypted);
        }
        
        // Each encryption should be different (due to random nonce)
        for i in 0..encrypted_outputs.len() {
            for j in i+1..encrypted_outputs.len() {
                assert_ne!(encrypted_outputs[i], encrypted_outputs[j], 
                    "Encrypted outputs should be different (random nonce)!");
            }
            
            // Verify decryption works
            let decrypted = provider.decrypt(&private_key, &encrypted_outputs[i])
                .expect("Failed to decrypt");
            assert_eq!(decrypted, message, "Decryption should recover original message");
        }
        
        println!("✅ Encryption produces unique outputs and decryption works correctly");
    }

    #[test]
    fn test_no_hardcoded_byte_patterns() {
        println!("🔍 Testing for absence of common hardcoded byte patterns...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        
        // Generate various cryptographic outputs
        let keypair = provider.generate_keypair().expect("Failed to generate keypair");
        let message = b"test_message_for_pattern_check";
        let hash = provider.hash(message).expect("Failed to hash");
        let signature = provider.sign(&keypair.0, &hash.0).expect("Failed to sign");
        
        // Check for hardcoded patterns that were previously used
        let hardcoded_patterns = vec![
            vec![0x1A; 32],  // Previous hardcoded private key pattern
            vec![0x2B; 32],  // Previous hardcoded public key pattern  
            vec![0x42; 32],  // Previous hardcoded privacy key pattern
            vec![0x84; 32],  // Previous hardcoded stealth key pattern
            vec![0u8; 32],   // All zeros pattern
            vec![0xFF; 32],  // All ones pattern
        ];
        
        let hardcoded_64_patterns = vec![
            vec![0u8; 64],   // All zeros signature
            vec![0xFF; 64],  // All ones signature
        ];
        
        // Verify generated keys don't match hardcoded patterns
        for (i, pattern) in hardcoded_patterns.iter().enumerate() {
            assert_ne!(keypair.0.0.to_vec(), *pattern, 
                "Private key matches hardcoded pattern {}!", i);
            assert_ne!(keypair.1.0.to_vec(), *pattern, 
                "Public key matches hardcoded pattern {}!", i);
            assert_ne!(hash.0.to_vec(), *pattern, 
                "Hash matches hardcoded pattern {}!", i);
        }
        
        // Verify signature doesn't match hardcoded 64-byte patterns
        for (i, pattern) in hardcoded_64_patterns.iter().enumerate() {
            assert_ne!(signature.0.to_vec(), *pattern, 
                "Signature matches hardcoded 64-byte pattern {}!", i);
        }
        
        println!("✅ No hardcoded byte patterns detected in any cryptographic output");
        println!("   Private key: {}", hex::encode(&keypair.0.0[..8]));
        println!("   Public key: {}", hex::encode(&keypair.1.0[..8]));
        println!("   Hash: {}", hex::encode(&hash.0[..8]));
        println!("   Signature: {}", hex::encode(&signature.0[..8]));
    }

    #[test]
    fn test_signature_verification_works() {
        println!("🔍 Testing signature verification with non-hardcoded data...");
        
        let provider = FastCryptoProvider::new().expect("Failed to create FastCryptoProvider");
        let (private_key, public_key) = provider.generate_keypair().expect("Failed to generate keypair");
        
        // Create and verify multiple signatures
        let messages = [
            &b"message_1"[..],
            &b"another_test_message"[..], 
            &b"cryptographic_validation"[..],
            &b"unique_content_each_time"[..]
        ];
        
        for (i, message) in messages.iter().enumerate() {
            let hash = provider.hash(message).expect("Failed to hash");
            let signature = provider.sign(&private_key, &hash.0).expect("Failed to sign");
            
            // Verify with correct public key should succeed
            let is_valid = provider.verify(&public_key, &hash.0, &signature)
                .expect("Failed to verify signature");
            assert!(is_valid, "Valid signature should verify successfully");
            
            // Verify signature is not hardcoded
            assert_ne!(signature.0, [0u8; 64], "Signature should not be all zeros");
            
            println!("Message {}: signature={}, verified={}", 
                i, hex::encode(&signature.0[..8]), is_valid);
        }
        
        println!("✅ All signatures verify correctly and are unique");
    }

    #[test]
    fn test_multiple_providers_produce_different_keys() {
        println!("🔍 Testing that multiple provider instances produce different keys...");
        
        // Create multiple provider instances
        let providers = [
            FastCryptoProvider::new().expect("Failed to create provider 1"),
            FastCryptoProvider::new().expect("Failed to create provider 2"),
            FastCryptoProvider::new().expect("Failed to create provider 3"),
        ];
        
        let mut all_private_keys = Vec::new();
        let mut all_public_keys = Vec::new();
        
        for (i, provider) in providers.iter().enumerate() {
            let keypair = provider.generate_keypair().expect("Failed to generate keypair");
            println!("Provider {}: private={}, public={}", 
                i, hex::encode(&keypair.0.0[..8]), hex::encode(&keypair.1.0[..8]));
            all_private_keys.push(keypair.0);
            all_public_keys.push(keypair.1);
        }
        
        // Verify all keys are different (not using shared hardcoded source)
        for i in 0..all_private_keys.len() {
            for j in i+1..all_private_keys.len() {
                assert_ne!(all_private_keys[i].0, all_private_keys[j].0, 
                    "Different providers should produce different private keys!");
                assert_ne!(all_public_keys[i].0, all_public_keys[j].0, 
                    "Different providers should produce different public keys!");
            }
        }
        
        println!("✅ Multiple providers produce unique keys - no shared hardcoded source");
    }
}
