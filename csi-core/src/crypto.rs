use base64::{engine::general_purpose::STANDARD as Base64, Engine};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::rngs::OsRng as RandOsRng;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keychain::{load_device_secret, store_device_secret};

const HIK_ACCOUNT: &str = "hardware_identity_key";
const HIK_VERSION_ACCOUNT: &str = "hardware_identity_version";

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

impl From<anyhow::Error> for CryptoError {
    fn from(e: anyhow::Error) -> Self {
        CryptoError::Keychain(e.to_string())
    }
}

#[derive(Clone)]
pub struct HardwareIdentity {
    secret: StaticSecret,
    public: PublicKey,
    pub version: u32,
}

impl HardwareIdentity {
    pub fn load_or_generate() -> Result<Self, CryptoError> {
        // Load HIK from device-bound Keychain or generate a new one if not present.
        match load_device_secret(HIK_ACCOUNT) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(CryptoError::KeyFormat("Invalid HIK length in keychain".into()));
                }
                let version = Self::load_version();
                let mut secret_bytes = [0u8; 32];
                secret_bytes.copy_from_slice(&bytes);
                let mut tmp = bytes;
                tmp.zeroize();

                let secret = StaticSecret::from(secret_bytes);
                let public = PublicKey::from(&secret);
                Ok(Self { secret, public, version })
            }
            Err(_) => Self::generate_and_store(0),
        }
    }

    fn generate_and_store(version: u32) -> Result<Self, CryptoError> {
        let secret = StaticSecret::random_from_rng(RandOsRng);
        let public = PublicKey::from(&secret);

        store_device_secret(HIK_ACCOUNT, secret.as_bytes())
            .map_err(|e| CryptoError::Keychain(e.to_string()))?;
        Self::store_version(version)
            .map_err(|e| CryptoError::Keychain(e.to_string()))?;

        Ok(Self { secret, public, version })
    }

    fn load_version() -> u32 {
        load_device_secret(HIK_VERSION_ACCOUNT)
            .ok()
            .and_then(|b| b.get(..4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])))
            .unwrap_or(0)
    }

    fn store_version(v: u32) -> anyhow::Result<()> {
        store_device_secret(HIK_VERSION_ACCOUNT, &v.to_le_bytes())
    }

    pub fn rotate(&mut self) -> Result<PublicKey, CryptoError> {
        let old_public = self.public;
        let new_version = self.version.saturating_add(1);
        let new_identity = Self::generate_and_store(new_version)?;
        self.secret = new_identity.secret;
        self.public = new_identity.public;
        self.version = new_version;
        Ok(old_public)
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
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

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

    pub fn as_base64(&self) -> String {
        Base64.encode(self.0)
    }
}
