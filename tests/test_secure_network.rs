// Integration tests for secure_network module
use shrowd_secret::secure_network::{SecureNetwork, NetworkPeer, TrustLevel};
use shrowd_secret::secret_config::FastCryptoProvider;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_network_creation() {
        let network = SecureNetwork::new("127.0.0.1:8080");
        assert!(network.is_ok());
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
    fn test_peer_registration() {
        let mut network = SecureNetwork::new("127.0.0.1:8080").unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (_, peer_public) = provider.generate_keypair().unwrap();
        
        let peer = NetworkPeer {
            peer_id: "peer_1".to_string(),
            public_key: peer_public,
            address: "127.0.0.1:8081".to_string(),
            trust_level: TrustLevel::Known,
            last_seen: 0,
            connection_count: 0,
            reputation: 50,
        };
        
        let registration = network.add_peer(peer);
        assert!(registration.is_ok());
    }

    #[test]
    fn test_secure_channel_creation() {
        let mut network = SecureNetwork::new("127.0.0.1:8080").unwrap();
        let provider = FastCryptoProvider::new().unwrap();
        let (_, peer_public) = provider.generate_keypair().unwrap();
        
        let peer = NetworkPeer {
            peer_id: "peer_1".to_string(),
            public_key: peer_public,
            address: "127.0.0.1:8081".to_string(),
            trust_level: TrustLevel::Known,
            last_seen: 0,
            connection_count: 0,
            reputation: 50,
        };
        
        // Register peer first
        network.add_peer(peer).unwrap();
        
        let channel = network.establish_channel("peer_1");
        assert!(channel.is_ok());
    }

    #[test]
    fn test_discovery_announcement() {
        let network = SecureNetwork::new("127.0.0.1:8080");
        // Just test that creation works - full discovery would need more implementation
        assert!(network.is_ok());
    }
}
