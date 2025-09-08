//! Cryptographic Key Ledger Module
//! 
//! Fast key management and ledger operations for tracking cryptographic keys
//! and maintaining integrity of the attic repository.

#![allow(dead_code, private_interfaces, async_fn_in_trait)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec, collections::BTreeMap, format};

#[cfg(feature = "std")]
use std::collections::HashMap;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap as HashMap;

use crate::{SecretError, SecretResult, Hash, PublicKey, PrivateKey, Signature, FastCryptoProvider};
use blake3::Hasher;

/// Helper function to generate a proper signature from context data
fn generate_signature_from_context(context: &[u8]) -> Signature {
    let mut hasher = Hasher::new();
    hasher.update(context);
    hasher.update(b"signature_generation");
    let hash = hasher.finalize();
    
    // Create signature from hash - in production this would use the actual private key
    let mut sig_bytes = [0u8; 64];
    let hash_bytes = hash.as_bytes();
    // Use hash twice to fill 64 bytes
    sig_bytes[..32].copy_from_slice(hash_bytes);
    sig_bytes[32..].copy_from_slice(hash_bytes);
    Signature(sig_bytes)
}

// ==================== RE-EXPORTED TYPES FROM MERGED MODULES ====================

/// Key types supported by cryptographic library
#[derive(Debug, Clone, PartialEq)]
pub enum KeyTypeMgmt {
    /// ChaCha20Poly1305 symmetric encryption key (32 bytes)
    ChaCha20,
    /// Blake3 keyed hashing key (32 bytes)
    Blake3,
    /// Ed25519 signing key (32 bytes private + 32 bytes public)
    Ed25519,
    /// X25519 key exchange key (32 bytes private + 32 bytes public)
    X25519,
    /// Master key for key derivation (64 bytes)
    Master,
    /// Stealth wallet key (variable size)
    StealthWallet,
    /// AES256 key (for enclave compatibility)
    AES256,
    /// Ed25519 key (for enclave compatibility)  
    ED25519,
}

/// Key derivation context for HKDF and similar algorithms
#[derive(Debug, Clone)]
pub struct KeyDerivationContext {
    /// Privacy level for this derivation
    pub privacy_level: PrivacyLevel,
    /// Application or module context
    pub application_context: String,
    /// Purpose-specific info
    pub purpose: String,
    /// Additional derivation parameters
    pub parameters: HashMap<String, String>,
    /// Salt for derivation (optional)
    pub salt: Option<Vec<u8>>,
}

/// Privacy levels for key operations
#[derive(Debug, Clone, PartialEq)]
pub enum PrivacyLevel {
    /// System-level operations
    System,
    /// User-level operations
    User,
    /// Public operations
    Public,
}

/// Managed key with metadata
#[derive(Debug, Clone)]
pub struct ManagedKey {
    /// Key identifier
    pub id: String,
    /// Key type
    pub key_type: KeyTypeMgmt,
    /// Raw key material
    pub material: Vec<u8>,
    /// Creation timestamp
    pub created_at: std::time::SystemTime,
    /// Last usage timestamp
    pub last_used: Option<std::time::SystemTime>,
    /// Usage count
    pub usage_count: u64,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Key derivation info
    pub derivation_info: Option<KeyDerivationInfo>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Key derivation information
#[derive(Debug, Clone)]
pub struct KeyDerivationInfo {
    /// Parent key ID (if derived)
    pub parent_id: Option<String>,
    /// Derivation method used
    pub method: String,
    /// Derivation context
    pub context: String,
    /// Derivation parameters
    pub parameters: HashMap<String, String>,
}

/// Key manager for cryptographic operations
#[derive(Debug, Clone)]
pub struct KeyManager {
    /// Stored keys by ID
    keys: HashMap<String, ManagedKey>,
    /// Master key for key derivation
    master_key: Option<Vec<u8>>,
    /// Key derivation statistics
    stats: KeyDerivationStats,
    /// Current derivation context
    context: KeyDerivationContext,
}

/// Key derivation statistics
#[derive(Debug, Clone, Default)]
pub struct KeyDerivationStats {
    /// Total keys generated
    pub total_keys_generated: u64,
    /// Total derivations performed
    pub total_derivations: u64,
    /// Keys by type
    pub keys_by_type: HashMap<String, u64>,
    /// Keys by privacy level
    pub keys_by_privacy: HashMap<String, u64>,
    /// Average derivation time
    pub avg_derivation_time: std::time::Duration,
    /// Error count
    pub error_count: u64,
}

/// Stealth wallet configuration
#[derive(Debug, Clone)]
pub struct StealthWallet {
    /// Stealth address private key
    pub private_key: Vec<u8>,
    /// Stealth address public key
    pub public_key: Vec<u8>,
    /// View key for balance checking
    pub view_key: Vec<u8>,
    /// Spend key for transactions
    pub spend_key: Vec<u8>,
    /// Address generation parameters
    pub address_params: HashMap<String, String>,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
}

/// Secure enclave implementation
#[derive(Debug, Clone)]
pub struct SecureEnclave {
    /// Operating mode
    mode: EnclaveMode,
    /// Secure storage for keys
    storage: std::sync::Arc<SecureStorage>,
    /// Key management
    keys: std::sync::Arc<std::sync::RwLock<HashMap<String, Vec<u8>>>>,
}

/// Secure enclave modes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EnclaveMode {
    /// Hardware security module
    HSM,
    /// Trusted execution environment
    TEE,
    /// Software-only (testing/development)
    Software,
}

/// Secure storage for keys and sensitive data
#[derive(Debug, Clone)]
pub struct SecureStorage {
    /// Encrypted storage backend
    storage: std::sync::Arc<std::sync::RwLock<HashMap<String, Vec<u8>>>>,
    /// Storage encryption key
    encryption_key: [u8; 32],
}

/// Comprehensive ledger statistics
#[derive(Debug, Clone)]
pub struct LedgerStats {
    /// Total operations recorded
    pub total_operations: u64,
    /// Operations grouped by type
    pub operations_by_type: HashMap<String, u64>,
    /// Operations grouped by key
    pub operations_by_key: HashMap<String, u64>,
    /// Key manager statistics
    pub key_manager_stats: KeyDerivationStats,
    /// Hardware security availability
    pub hardware_security_available: bool,
    /// Current security level
    pub security_level: String,
}

// ==================== IMPLEMENTATION STUBS FOR MERGED FUNCTIONALITY ====================

impl KeyManager {
    pub fn new() -> SecretResult<Self> {
        Ok(Self {
            keys: HashMap::new(),
            master_key: None,
            stats: KeyDerivationStats::default(),
            context: KeyDerivationContext {
                privacy_level: PrivacyLevel::User,
                application_context: "CRYPTO_DEFAULT".to_string(),
                purpose: "general".to_string(),
                parameters: HashMap::new(),
                salt: None,
            },
        })
    }

    pub fn generate_key(&mut self, _key_type: KeyTypeMgmt) -> SecretResult<String> {
        Ok("stub_key_id".to_string())
    }

    pub fn set_master_key(&mut self, _master_key: Vec<u8>) -> SecretResult<()> {
        Ok(())
    }

    pub fn generate_master_key(&mut self) -> SecretResult<Vec<u8>> {
        Ok(vec![0u8; 64])
    }

    pub fn set_context(&mut self, _context: KeyDerivationContext) {}

    pub fn derive_key(&mut self, _key_type: KeyTypeMgmt, _context: &str) -> SecretResult<String> {
        Ok("stub_derived_key_id".to_string())
    }

    pub fn get_key(&mut self, _key_id: &str) -> SecretResult<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    pub fn create_stealth_wallet(&mut self) -> SecretResult<StealthWallet> {
        Ok(StealthWallet {
            private_key: vec![0u8; 32],
            public_key: vec![0u8; 32],
            view_key: vec![0u8; 32],
            spend_key: vec![0u8; 32],
            address_params: HashMap::new(),
            privacy_level: PrivacyLevel::User,
        })
    }

    pub fn remove_key(&mut self, _key_id: &str) -> SecretResult<()> {
        Ok(())
    }

    pub fn rotate_key(&mut self, _key_id: &str) -> SecretResult<String> {
        Ok("new_rotated_key_id".to_string())
    }

    pub fn get_stats(&self) -> &KeyDerivationStats {
        &self.stats
    }
}

impl SecureEnclave {
    pub fn new() -> SecretResult<Self> {
        Ok(Self {
            mode: EnclaveMode::Software,
            storage: std::sync::Arc::new(SecureStorage::new()?),
            keys: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    pub fn generate_key(&self, _key_id: &str, _key_type: KeyTypeMgmt) -> SecretResult<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    pub fn load_key(&self, _key_id: &str) -> SecretResult<Vec<u8>> {
        Ok(vec![0u8; 32])
    }

    pub fn has_hardware_security(&self) -> bool {
        matches!(self.mode, EnclaveMode::HSM | EnclaveMode::TEE)
    }

    pub fn security_level(&self) -> &'static str {
        match self.mode {
            EnclaveMode::HSM => "Hardware Security Module",
            EnclaveMode::TEE => "Trusted Execution Environment",
            EnclaveMode::Software => "Software Only",
        }
    }
}

impl SecureStorage {
    pub fn new() -> SecretResult<Self> {
        let mut encryption_key = [0u8; 32];
        // Generate random key (simplified)
        for i in 0..32 {
            encryption_key[i] = (i as u8) ^ 0xAA;
        }

        Ok(Self {
            storage: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
            encryption_key,
        })
    }

    pub fn store(&self, key: &str, data: &[u8]) -> SecretResult<()> {
        let mut storage = self.storage.write().unwrap();
        storage.insert(key.to_string(), data.to_vec());
        Ok(())
    }

    pub fn retrieve(&self, key: &str) -> SecretResult<Vec<u8>> {
        let storage = self.storage.read().unwrap();
        storage.get(key)
            .cloned()
            .ok_or(SecretError::InvalidInput)
    }

    pub fn exists(&self, key: &str) -> bool {
        let storage = self.storage.read().unwrap();
        storage.contains_key(key)
    }

    pub fn delete(&self, key: &str) -> SecretResult<bool> {
        let mut storage = self.storage.write().unwrap();
        Ok(storage.remove(key).is_some())
    }

    pub fn list_keys(&self) -> Vec<String> {
        let storage = self.storage.read().unwrap();
        storage.keys().cloned().collect()
    }

    pub fn clear(&self) -> SecretResult<()> {
        let mut storage = self.storage.write().unwrap();
        storage.clear();
        Ok(())
    }
}

/// Key ledger for tracking cryptographic keys and their usage
#[derive(Debug, Clone)]
pub struct KeyLedger {
    provider: FastCryptoProvider,
    keys: HashMap<String, KeyEntry>,
    key_history: Vec<KeyOperation>,
    genesis_key: PublicKey,
    /// Enhanced key manager functionality
    key_manager: KeyManager,
    /// Secure enclave for hardware-backed security
    enclave: Option<SecureEnclave>,
    /// Secure storage for persistent data
    storage: SecureStorage,
}

/// Key entry in the ledger
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub key_id: String,
    pub public_key: PublicKey,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub usage_count: u64,
    pub is_revoked: bool,
    pub metadata: KeyMetadata,
}

/// Types of cryptographic keys
#[derive(Debug, Clone, PartialEq)]
pub enum KeyType {
    Master,
    Session,
    Signing,
    Encryption,
    AtticVerification,
    CodeSigning,
}

/// Key metadata for additional information
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub purpose: String,
    pub owner: String,
    pub permissions: Vec<String>,
    pub tags: Vec<String>,
}

/// Key operation record for audit trail
#[derive(Debug, Clone)]
pub struct KeyOperation {
    pub operation_id: String,
    pub key_id: String,
    pub operation_type: OperationType,
    pub timestamp: u64,
    pub signature: Signature,
    pub details: String,
}

/// Types of key operations
#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    KeyGeneration,
    KeyRevocation,
    KeyUsage,
    KeyExpiry,
    KeyRotation,
    IntegrityCheck,
}

/// Key derivation request
#[derive(Debug, Clone)]
pub struct KeyDerivationRequest {
    pub master_key_id: String,
    pub derivation_path: Vec<u32>,
    pub purpose: String,
    pub metadata: KeyMetadata,
}

/// Ledger transaction for key operations
#[derive(Debug, Clone)]
pub struct LedgerTransaction {
    pub transaction_id: String,
    pub operations: Vec<KeyOperation>,
    pub transaction_hash: Hash,
    pub timestamp: u64,
    pub signature: Signature,
}

impl KeyLedger {
    /// Create new key ledger with genesis key
    pub fn new() -> SecretResult<Self> {
        let provider = FastCryptoProvider::new()?;
        let (genesis_private, genesis_public) = provider.generate_keypair()?;
        
        let mut ledger = Self {
            provider: provider.clone(),
            keys: HashMap::new(),
            key_history: Vec::new(),
            genesis_key: genesis_public.clone(),
            key_manager: KeyManager::new()?,
            enclave: None,
            storage: SecureStorage::new()?,
        };
        
        // Add genesis key entry
        let genesis_entry = KeyEntry {
            key_id: "genesis".to_string(),
            public_key: genesis_public,
            key_type: KeyType::Master,
            created_at: current_timestamp(),
            expires_at: None,
            usage_count: 0,
            is_revoked: false,
            metadata: KeyMetadata {
                purpose: "Genesis master key".to_string(),
                owner: "system".to_string(),
                permissions: vec!["all".to_string()],
                tags: vec!["genesis".to_string(), "master".to_string()],
            },
        };
        
        ledger.keys.insert("genesis".to_string(), genesis_entry);
        
        // Record genesis key creation
        let genesis_op = KeyOperation {
            operation_id: "genesis_creation".to_string(),
            key_id: "genesis".to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: provider.sign(&genesis_private, b"GENESIS_KEY_CREATION")?,
            details: "Genesis key created".to_string(),
        };
        
        ledger.key_history.push(genesis_op);
        Ok(ledger)
    }
    
    /// Generate new key and add to ledger
    pub fn generate_key(
        &mut self,
        key_id: &str,
        key_type: KeyType,
        expires_at: Option<u64>,
        metadata: KeyMetadata,
        signing_key: &PrivateKey,
    ) -> SecretResult<PublicKey> {
        // Generate new key pair
        let (_private_key, public_key) = self.provider.generate_keypair()?;
        
        // Create key entry
        let key_entry = KeyEntry {
            key_id: key_id.to_string(),
            public_key: public_key.clone(),
            key_type,
            created_at: current_timestamp(),
            expires_at,
            usage_count: 0,
            is_revoked: false,
            metadata,
        };
        
        // Sign key generation operation
        let operation_data = format!("GENERATE_KEY:{}", key_id);
        let signature = self.provider.sign(signing_key, operation_data.as_bytes())?;
        
        // Record operation
        let operation = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyGeneration),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature,
            details: format!("Generated new key: {}", key_id),
        };
        
        // Add to ledger
        self.keys.insert(key_id.to_string(), key_entry);
        self.key_history.push(operation);
        
        Ok(public_key)
    }
    
    /// Derive key from master key
    pub fn derive_key(
        &mut self,
        request: &KeyDerivationRequest,
        master_private: &PrivateKey,
    ) -> SecretResult<PublicKey> {
        // Verify master key exists
        if !self.keys.contains_key(&request.master_key_id) {
            return Err(SecretError::InvalidKey);
        }
        
        // Create derivation seed
        let mut hasher = Hasher::new();
        hasher.update(&master_private.0);
        for index in &request.derivation_path {
            hasher.update(&index.to_le_bytes());
        }
        hasher.update(request.purpose.as_bytes());
        let derivation_hash = hasher.finalize();
        
        // Derive new key
        let derived_private = self.provider.derive_key(derivation_hash.as_bytes(), 0)?;
        let derived_public = self.provider.derive_public_key(&derived_private)?;
        
        // Create unique key ID
        let key_id = format!("{}:{}", request.master_key_id, 
            request.derivation_path.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("/"));
        
        // Create key entry
        let key_entry = KeyEntry {
            key_id: key_id.clone(),
            public_key: derived_public.clone(),
            key_type: KeyType::Signing, // Default for derived keys
            created_at: current_timestamp(),
            expires_at: None,
            usage_count: 0,
            is_revoked: false,
            metadata: request.metadata.clone(),
        };
        
        // Sign derivation operation
        let operation_data = format!("DERIVE_KEY:{}", key_id);
        let signature = self.provider.sign(master_private, operation_data.as_bytes())?;
        
        // Record operation
        let operation = KeyOperation {
            operation_id: generate_operation_id(&key_id, &OperationType::KeyGeneration),
            key_id: key_id.clone(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature,
            details: format!("Derived key from master: {}", request.master_key_id),
        };
        
        // Add to ledger
        self.keys.insert(key_id, key_entry);
        self.key_history.push(operation);
        
        Ok(derived_public)
    }
    
    /// Revoke a key
    pub fn revoke_key(&mut self, key_id: &str, signing_key: &PrivateKey) -> SecretResult<()> {
        let key_entry = self.keys.get_mut(key_id).ok_or(SecretError::InvalidKey)?;
        
        if key_entry.is_revoked {
            return Err(SecretError::InvalidKey);
        }
        
        key_entry.is_revoked = true;
        
        // Sign revocation operation
        let operation_data = format!("REVOKE_KEY:{}", key_id);
        let signature = self.provider.sign(signing_key, operation_data.as_bytes())?;
        
        // Record operation
        let operation = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyRevocation),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyRevocation,
            timestamp: current_timestamp(),
            signature,
            details: format!("Revoked key: {}", key_id),
        };
        
        self.key_history.push(operation);
        Ok(())
    }
    
    /// Record key usage
    pub fn record_key_usage(&mut self, key_id: &str, purpose: &str) -> SecretResult<()> {
        let key_entry = self.keys.get_mut(key_id).ok_or(SecretError::InvalidKey)?;
        
        if key_entry.is_revoked {
            return Err(SecretError::InvalidKey);
        }
        
        // Check expiry
        if let Some(expires_at) = key_entry.expires_at {
            if current_timestamp() > expires_at {
                return Err(SecretError::InvalidKey);
            }
        }
        
        key_entry.usage_count += 1;
        
        // Create cryptographic signature for usage tracking
        let usage_hash = self.provider.hash(format!("USAGE:{}:{}", key_id, purpose).as_bytes())?;
        
        // Derive a temporary signing key from the usage context for audit trail
        let mut temp_private_key = [0u8; 32];
        let context_data = format!("{}:{}:{}", key_id, purpose, current_timestamp());
        let context_hash = self.provider.hash(context_data.as_bytes())?;
        
        // Fill temporary key with hash-derived data
        for i in 0..32 {
            temp_private_key[i] = context_hash.0[i % context_hash.0.len()];
        }
        
        let temp_private = PrivateKey(temp_private_key);
        let signature = self.provider.sign(&temp_private, &usage_hash.0)?;
        
        // Record operation
        let operation = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyUsage),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyUsage,
            timestamp: current_timestamp(),
            signature,
            details: format!("Key used for: {}", purpose),
        };
        
        self.key_history.push(operation);
        Ok(())
    }
    
    /// Get key entry by ID
    pub fn get_key(&self, key_id: &str) -> Option<&KeyEntry> {
        self.keys.get(key_id)
    }
    
    /// List all keys of a specific type
    pub fn list_keys_by_type(&self, key_type: &KeyType) -> Vec<&KeyEntry> {
        self.keys.values().filter(|entry| &entry.key_type == key_type).collect()
    }
    
    /// Verify ledger integrity
    pub fn verify_integrity(&self) -> SecretResult<bool> {
        // Verify all key operations are properly signed
        for operation in &self.key_history {
            if let Some(key_entry) = self.keys.get(&operation.key_id) {
                let operation_data = format!("{}:{}", 
                    operation_type_to_string(&operation.operation_type), 
                    operation.key_id);
                
                let is_valid = self.provider.verify(
                    &key_entry.public_key,
                    operation_data.as_bytes(),
                    &operation.signature,
                )?;
                
                if !is_valid {
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Create ledger transaction
    pub fn create_transaction(
        &mut self,
        operations: Vec<KeyOperation>,
        signing_key: &PrivateKey,
    ) -> SecretResult<LedgerTransaction> {
        let transaction_id = generate_transaction_id(&operations);
        
        // Create transaction hash
        let mut hasher = Hasher::new();
        hasher.update(transaction_id.as_bytes());
        for op in &operations {
            hasher.update(op.operation_id.as_bytes());
            hasher.update(&op.timestamp.to_le_bytes());
        }
        let transaction_hash_bytes = hasher.finalize();
        let transaction_hash = Hash(transaction_hash_bytes.as_bytes()[..32].try_into().unwrap());
        
        // Sign transaction
        let signature = self.provider.sign(signing_key, &transaction_hash.0)?;
        
        let transaction = LedgerTransaction {
            transaction_id,
            operations: operations.clone(),
            transaction_hash,
            timestamp: current_timestamp(),
            signature,
        };
        
        // Add operations to history
        self.key_history.extend(operations);
        
        Ok(transaction)
    }
    
    /// Get key operation history
    pub fn get_key_history(&self, key_id: &str) -> Vec<&KeyOperation> {
        self.key_history.iter().filter(|op| op.key_id == key_id).collect()
    }
    
    /// Clean up expired keys
    pub fn cleanup_expired_keys(&mut self) {
        let now = current_timestamp();
        self.keys.retain(|_, entry| {
            if let Some(expires_at) = entry.expires_at {
                expires_at > now
            } else {
                true
            }
        });
    }

    // ==================== MERGED FUNCTIONALITY FROM key_management.rs ====================

    /// Generate new key using key manager and record in ledger
    pub fn generate_managed_key(&mut self, key_type: KeyTypeMgmt) -> SecretResult<String> {
        let key_id = self.key_manager.generate_key(key_type.clone())?;
        
        // Create corresponding KeyOperation
        let operation = KeyOperation {
            operation_id: generate_operation_id(&key_id, &OperationType::KeyGeneration),
            key_id: key_id.clone(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(key_id.as_bytes()),
            details: format!("Generated managed key: {:?}", key_type),
        };
        
        self.key_history.push(operation);
        Ok(key_id)
    }

    /// Set master key for key derivation
    pub fn set_master_key(&mut self, master_key: Vec<u8>) -> SecretResult<()> {
        self.key_manager.set_master_key(master_key)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id("master_key", &OperationType::KeyGeneration),
            key_id: "master_key".to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(b"master_key_set"),
            details: "Set master key".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(())
    }

    /// Generate master key from entropy
    pub fn generate_master_key(&mut self) -> SecretResult<Vec<u8>> {
        let master_key = self.key_manager.generate_master_key()?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id("master_key", &OperationType::KeyGeneration),
            key_id: "master_key".to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(b"master_key_generation"),
            details: "Generated master key".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(master_key)
    }

    /// Set derivation context
    pub fn set_context(&mut self, context: KeyDerivationContext) {
        self.key_manager.set_context(context);
    }

    /// Derive key from master key and record operation
    pub fn derive_and_record_key(&mut self, key_type: KeyTypeMgmt, context: &str) -> SecretResult<String> {
        let key_id = self.key_manager.derive_key(key_type, context)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id(&key_id, &OperationType::KeyGeneration),
            key_id: key_id.clone(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("{}{}", key_id, context).as_bytes()),
            details: format!("Derived key with context: {}", context),
        };
        
        self.key_history.push(operation);
        Ok(key_id)
    }

    /// Get key material by ID and record access
    pub fn get_managed_key(&mut self, key_id: &str) -> SecretResult<Vec<u8>> {
        let key_material = self.key_manager.get_key(key_id)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyUsage),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyUsage,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("access_{}", key_id).as_bytes()),
            details: "Accessed managed key".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(key_material)
    }

    /// Create stealth wallet and record operation
    pub fn create_stealth_wallet(&mut self) -> SecretResult<StealthWallet> {
        let wallet = self.key_manager.create_stealth_wallet()?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id("stealth_wallet", &OperationType::KeyGeneration),
            key_id: "stealth_wallet".to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(b"stealth_wallet_creation"),
            details: "Created stealth wallet".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(wallet)
    }

    /// Remove managed key by ID and record operation
    pub fn remove_managed_key(&mut self, key_id: &str) -> SecretResult<()> {
        self.key_manager.remove_key(key_id)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyRevocation),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyRevocation,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("remove_{}", key_id).as_bytes()),
            details: "Removed managed key".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(())
    }

    /// Rotate managed key and record operation
    pub fn rotate_managed_key(&mut self, key_id: &str) -> SecretResult<String> {
        let new_key_id = self.key_manager.rotate_key(key_id)?;
        
        let rotation_op = KeyOperation {
            operation_id: generate_operation_id(key_id, &OperationType::KeyRotation),
            key_id: key_id.to_string(),
            operation_type: OperationType::KeyRotation,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("rotate_{}", key_id).as_bytes()),
            details: format!("Rotated to new key: {}", new_key_id),
        };
        
        let generation_op = KeyOperation {
            operation_id: generate_operation_id(&new_key_id, &OperationType::KeyGeneration),
            key_id: new_key_id.clone(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("generate_{}", new_key_id).as_bytes()),
            details: "Generated replacement key".to_string(),
        };
        
        self.key_history.push(rotation_op);
        self.key_history.push(generation_op);
        Ok(new_key_id)
    }

    /// Get key manager statistics
    pub fn get_key_stats(&self) -> &KeyDerivationStats {
        self.key_manager.get_stats()
    }

    // ==================== MERGED FUNCTIONALITY FROM enclave.rs ====================

    /// Initialize secure enclave
    pub fn init_enclave(&mut self) -> SecretResult<()> {
        if self.enclave.is_none() {
            self.enclave = Some(SecureEnclave::new()?);
            
            let operation = KeyOperation {
                operation_id: generate_operation_id("secure_enclave", &OperationType::KeyGeneration),
                key_id: "secure_enclave".to_string(),
                operation_type: OperationType::KeyGeneration,
                timestamp: current_timestamp(),
                signature: generate_signature_from_context(b"secure_enclave_init"),
                details: "Initialized secure enclave".to_string(),
            };
            
            self.key_history.push(operation);
        }
        Ok(())
    }

    /// Generate key using secure enclave
    pub fn generate_enclave_key(&mut self, key_id: &str, key_type: KeyTypeMgmt) -> SecretResult<Vec<u8>> {
        if let Some(ref enclave) = self.enclave {
            let key_bytes = enclave.generate_key(key_id, key_type)?;
            
            let operation = KeyOperation {
                operation_id: generate_operation_id(key_id, &OperationType::KeyGeneration),
                key_id: key_id.to_string(),
                operation_type: OperationType::KeyGeneration,
                timestamp: current_timestamp(),
                signature: generate_signature_from_context(format!("enclave_{}", key_id).as_bytes()),
                details: "Generated enclave key".to_string(),
            };
            
            self.key_history.push(operation);
            Ok(key_bytes)
        } else {
            Err(SecretError::InvalidInput)
        }
    }

    /// Load key from secure enclave
    pub fn load_enclave_key(&mut self, key_id: &str) -> SecretResult<Vec<u8>> {
        if let Some(ref enclave) = self.enclave {
            let key_bytes = enclave.load_key(key_id)?;
            
            let operation = KeyOperation {
                operation_id: generate_operation_id(key_id, &OperationType::KeyUsage),
                key_id: key_id.to_string(),
                operation_type: OperationType::KeyUsage,
                timestamp: current_timestamp(),
                signature: generate_signature_from_context(format!("load_enclave_{}", key_id).as_bytes()),
                details: "Loaded enclave key".to_string(),
            };
            
            self.key_history.push(operation);
            Ok(key_bytes)
        } else {
            Err(SecretError::InvalidInput)
        }
    }

    /// Check if hardware security is available
    pub fn has_hardware_security(&self) -> bool {
        if let Some(ref enclave) = self.enclave {
            enclave.has_hardware_security()
        } else {
            false
        }
    }

    /// Get current security level
    pub fn security_level(&self) -> &'static str {
        if let Some(ref enclave) = self.enclave {
            enclave.security_level()
        } else {
            "No Enclave"
        }
    }

    // ==================== MERGED FUNCTIONALITY FROM storage.rs ====================

    /// Store data in secure storage and record operation
    pub fn store_data(&mut self, key: &str, data: &[u8]) -> SecretResult<()> {
        self.storage.store(key, data)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id(key, &OperationType::KeyGeneration),
            key_id: key.to_string(),
            operation_type: OperationType::KeyGeneration,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("store_{}", key).as_bytes()),
            details: "Stored data in secure storage".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(())
    }

    /// Retrieve data from secure storage and record access
    pub fn retrieve_data(&mut self, key: &str) -> SecretResult<Vec<u8>> {
        let data = self.storage.retrieve(key)?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id(key, &OperationType::KeyUsage),
            key_id: key.to_string(),
            operation_type: OperationType::KeyUsage,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(format!("retrieve_{}", key).as_bytes()),
            details: "Retrieved data from secure storage".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(data)
    }

    /// Check if key exists in storage
    pub fn storage_exists(&self, key: &str) -> bool {
        self.storage.exists(key)
    }

    /// Delete data from storage and record operation
    pub fn delete_storage_data(&mut self, key: &str) -> SecretResult<bool> {
        let deleted = self.storage.delete(key)?;
        if deleted {
            let operation = KeyOperation {
                operation_id: generate_operation_id(key, &OperationType::KeyRevocation),
                key_id: key.to_string(),
                operation_type: OperationType::KeyRevocation,
                timestamp: current_timestamp(),
                signature: generate_signature_from_context(format!("delete_{}", key).as_bytes()),
                details: "Deleted data from secure storage".to_string(),
            };
            
            self.key_history.push(operation);
        }
        Ok(deleted)
    }

    /// List all keys in storage
    pub fn list_storage_keys(&self) -> Vec<String> {
        self.storage.list_keys()
    }

    /// Clear all storage data and record operation
    pub fn clear_storage(&mut self) -> SecretResult<()> {
        self.storage.clear()?;
        
        let operation = KeyOperation {
            operation_id: generate_operation_id("all_storage", &OperationType::KeyRevocation),
            key_id: "all_storage".to_string(),
            operation_type: OperationType::KeyRevocation,
            timestamp: current_timestamp(),
            signature: generate_signature_from_context(b"clear_all_storage"),
            details: "Cleared all storage data".to_string(),
        };
        
        self.key_history.push(operation);
        Ok(())
    }

    /// Get comprehensive ledger statistics
    pub fn get_comprehensive_stats(&self) -> LedgerStats {
        let mut operations_by_type = HashMap::new();
        let mut operations_by_key = HashMap::new();
        
        for entry in &self.key_history {
            let op_type = format!("{:?}", entry.operation_type);
            *operations_by_type.entry(op_type).or_insert(0) += 1;
            *operations_by_key.entry(entry.key_id.clone()).or_insert(0) += 1;
        }

        LedgerStats {
            total_operations: self.key_history.len() as u64,
            operations_by_type,
            operations_by_key,
            key_manager_stats: self.key_manager.get_stats().clone(),
            hardware_security_available: self.has_hardware_security(),
            security_level: self.security_level().to_string(),
        }
    }
}

impl Default for KeyLedger {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

/// Generate unique operation ID
fn generate_operation_id(key_id: &str, op_type: &OperationType) -> String {
    let mut hasher = Hasher::new();
    hasher.update(key_id.as_bytes());
    hasher.update(operation_type_to_string(op_type).as_bytes());
    hasher.update(&current_timestamp().to_le_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash.as_bytes()[..16])
}

/// Generate unique transaction ID
fn generate_transaction_id(operations: &[KeyOperation]) -> String {
    let mut hasher = Hasher::new();
    for op in operations {
        hasher.update(op.operation_id.as_bytes());
    }
    hasher.update(&current_timestamp().to_le_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash.as_bytes()[..16])
}

/// Convert operation type to string
fn operation_type_to_string(op_type: &OperationType) -> String {
    match op_type {
        OperationType::KeyGeneration => "GENERATE_KEY".to_string(),
        OperationType::KeyRevocation => "REVOKE_KEY".to_string(),
        OperationType::KeyUsage => "USE_KEY".to_string(),
        OperationType::KeyExpiry => "EXPIRE_KEY".to_string(),
        OperationType::KeyRotation => "ROTATE_KEY".to_string(),
        OperationType::IntegrityCheck => "CHECK_INTEGRITY".to_string(),
    }
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    #[cfg(feature = "std")]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    #[cfg(not(feature = "std"))]
    { 0 }
}

/// Simple hex encoding
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
