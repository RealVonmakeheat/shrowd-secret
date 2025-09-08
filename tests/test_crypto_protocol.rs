// Integration tests for crypto_protocol module
use shrowd_secret::secret_config::*;
use shrowd_secret::crypto_protocol::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_protocol_creation() {
        let protocol = CryptoProtocol::new();
        assert!(protocol.is_ok());
    }

    #[test]
    fn test_session_key_generation() {
        let mut protocol = CryptoProtocol::new().unwrap();
        let session_key = protocol.generate_session_key("test_session", 3600);
        assert!(session_key.is_ok());
        
        let key = session_key.unwrap();
        assert_eq!(key.key_id, "test_session");
        assert!(key.expires_at > key.created_at);
    }

    #[test]
    fn test_message_encryption() {
        let protocol = CryptoProtocol::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (sender_private, _) = provider.generate_keypair().unwrap();
        let (_, recipient_public) = provider.generate_keypair().unwrap();
        
        let message = b"test message";
        let encrypted = protocol.encrypt_message(
            &sender_private,
            &recipient_public,
            message
        );
        assert!(encrypted.is_ok());
    }

    #[test]
    fn test_message_decryption() {
        let protocol = CryptoProtocol::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (sender_private, _) = provider.generate_keypair().unwrap();
        let (recipient_private, recipient_public) = provider.generate_keypair().unwrap();
        
        let message = b"test message";
        let encrypted = protocol.encrypt_message(
            &sender_private,
            &recipient_public,
            message
        ).unwrap();
        
        let decrypted = protocol.decrypt_message(&recipient_private, &encrypted);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), message);
    }

    #[test]
    fn test_message_auth_creation() {
        let protocol = CryptoProtocol::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (private_key, _) = provider.generate_keypair().unwrap();
        let data = b"test data";
        
        let auth = protocol.create_message_auth(&private_key, data);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_message_auth_verification() {
        let protocol = CryptoProtocol::new().unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (private_key, _) = provider.generate_keypair().unwrap();
        let data = b"test data";
        
        let auth = protocol.create_message_auth(&private_key, data).unwrap();
        let verification = protocol.verify_message_auth(data, &auth);
        assert!(verification.is_ok());
        assert!(verification.unwrap());
    }
}
