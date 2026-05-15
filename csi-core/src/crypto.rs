use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use keyring::Entry;
use rand::rngs::OsRng as RandOsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Keychain error: {0}")]
    Keychain(String),
    #[error("Key format error: {0}")]
    KeyFormat(String),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
}

pub struct HardwareIdentity {
    secret: StaticSecret,
    public: PublicKey,
}

impl HardwareIdentity {
    const SERVICE_NAME: &'static str = "com.csi.tray-macos";
    const ACCOUNT_NAME: &'static str = "hardware_identity";

    pub fn load_or_generate() -> Result<Self, CryptoError> {
        let entry = Entry::new(Self::SERVICE_NAME, Self::ACCOUNT_NAME)
            .map_err(|e| CryptoError::Keychain(e.to_string()))?;

        match entry.get_password() {
            Ok(b64_secret) => {
                let bytes = Base64.decode(b64_secret)
                    .map_err(|e| CryptoError::KeyFormat(e.to_string()))?;
                
                if bytes.len() != 32 {
                    return Err(CryptoError::KeyFormat("Invalid key length".into()));
                }
                
                let mut secret_bytes = [0u8; 32];
                secret_bytes.copy_from_slice(&bytes);
                
                let secret = StaticSecret::from(secret_bytes);
                let public = PublicKey::from(&secret);
                
                Ok(Self { secret, public })
            }
            Err(_) => {
                // Generate new key
                let secret = StaticSecret::random_from_rng(RandOsRng);
                let public = PublicKey::from(&secret);
                
                let b64_secret = Base64.encode(secret.to_bytes());
                entry.set_password(&b64_secret)
                    .map_err(|e| CryptoError::Keychain(e.to_string()))?;
                
                Ok(Self { secret, public })
            }
        }
    }

    pub fn export_public_hik(&self) -> String {
        Base64.encode(self.public.as_bytes())
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }
    
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PersonalNetworkKey(pub [u8; 32]);

impl PersonalNetworkKey {
    pub fn new_random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        RandOsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn wrap(&self, target_public: &PublicKey, sender_secret: &StaticSecret) -> Result<Vec<u8>, CryptoError> {
        let shared_secret = sender_secret.diffie_hellman(target_public);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 12-bytes
        
        let mut ciphertext = cipher.encrypt(&nonce, self.0.as_ref())
            .map_err(|_| CryptoError::EncryptionFailed)?;
            
        let mut result = nonce.to_vec();
        result.append(&mut ciphertext);
        
        Ok(result)
    }

    pub fn unwrap(wrapped: &[u8], sender_public: &PublicKey, recipient_secret: &StaticSecret) -> Result<Self, CryptoError> {
        if wrapped.len() < 12 {
            return Err(CryptoError::DecryptionFailed);
        }
        
        let shared_secret = recipient_secret.diffie_hellman(sender_public);
        let cipher = ChaCha20Poly1305::new(shared_secret.as_bytes().into());
        
        let nonce = Nonce::from_slice(&wrapped[..12]);
        let ciphertext = &wrapped[12..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)?;
            
        if plaintext.len() != 32 {
            return Err(CryptoError::DecryptionFailed);
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        
        Ok(Self(key))
    }
}
