use shrowd_secret::secret_config::*;

fn main() -> SecretResult<()> {
    println!("SHROWD Secret Key Generation with 30-Word Mnemonic");
    println!("==================================================");
    
    // Generate a new key pair with mnemonic
    let (master_keypair, mnemonic) = KeyPair::generate_with_mnemonic()?;
    
    println!("✅ Generated Master Key Pair with Mnemonic Recovery");
    println!("🔑 Public Key: {:?}", hex::encode(&master_keypair.public.0));
    println!("📝 30-Word Mnemonic Phrase:");
    println!("   {}", mnemonic.to_string());
    println!();
    
    // Test recovery from mnemonic
    let recovered_keypair = KeyPair::from_mnemonic(&mnemonic, None)?;
    
    println!("✅ Successfully Recovered Key Pair from Mnemonic");
    println!("🔄 Recovered Public Key: {:?}", hex::encode(&recovered_keypair.public.0));
    
    // Verify they match
    assert_eq!(master_keypair.public.0, recovered_keypair.public.0);
    assert_eq!(master_keypair.private.0, recovered_keypair.private.0);
    println!("✅ Keys Match - Recovery Successful!");
    println!();
    
    // Generate specialized keys from the same mnemonic
    let signing_keypair = KeyPair::signing_keypair_from_mnemonic(&mnemonic, None)?;
    let encryption_keypair = KeyPair::encryption_keypair_from_mnemonic(&mnemonic, None)?;
    
    println!("🔐 Derived Specialized Keys:");
    println!("   Signing Key: {:?}", hex::encode(&signing_keypair.public.0));
    println!("   Encryption Key: {:?}", hex::encode(&encryption_keypair.public.0));
    println!();
    
    // Test with passphrase
    let passphrase = "my_secure_passphrase";
    let protected_keypair = KeyPair::from_mnemonic(&mnemonic, Some(passphrase))?;
    
    println!("🛡️  Generated Passphrase-Protected Key:");
    println!("   Protected Public Key: {:?}", hex::encode(&protected_keypair.public.0));
    
    // Verify different from unprotected
    assert_ne!(master_keypair.public.0, protected_keypair.public.0);
    println!("✅ Passphrase Protection Working - Keys are Different");
    println!();
    
    // Test full recovery data
    let generator = MnemonicKeyGenerator::new();
    let recovery_data = generator.generate_keys_from_mnemonic(&mnemonic, None)?;
    
    println!("📊 Complete Recovery Data:");
    println!("   Master Key: {:?}", hex::encode(&recovery_data.derived_keys.master_key.0));
    println!("   Signing Key: {:?}", hex::encode(&recovery_data.derived_keys.signing_key.0));
    println!("   Encryption Key: {:?}", hex::encode(&recovery_data.derived_keys.encryption_key.0));
    println!("   Authentication Key: {:?}", hex::encode(&recovery_data.derived_keys.authentication_key.0));
    println!("   Recovery Key: {:?}", hex::encode(&recovery_data.derived_keys.recovery_key.0));
    println!();
    
    // Test mnemonic validation
    assert!(generator.validate_mnemonic(&mnemonic)?);
    println!("✅ Mnemonic Validation Passed");
    
    // Test word access
    println!("🔤 First 5 words of mnemonic:");
    for i in 0..5 {
        if let Some(word) = mnemonic.get_word(i) {
            println!("   {}: {}", i + 1, word);
        }
    }
    
    println!();
    println!("🎉 All Mnemonic Key Generation Features Working!");
    println!("📈 Word List Size: {} words", generator.wordlist_size());
    println!("🔗 Includes hyphenated words for enhanced security");
    
    Ok(())
}

// Helper function to convert bytes to hex string
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
