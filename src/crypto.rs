//! Cryptographic primitives required by the Noise protocol.
//!
//! The crate supports the full set of primitives that appear in the official
//! cacophony test vector file:
//!
//! * DH: X25519 and X448
//! * Cipher: ChaCha20-Poly1305 and AES-256-GCM
//! * Hash: BLAKE2s-256, BLAKE2b-512, SHA-256 and SHA-512
//!
//! Only "Noise"-style usage is exposed: the DH function returns raw bytes, the
//! AEAD takes an explicit 64-bit nonce and the caller is responsible for
//! enforcing nonce limits (see [`crate::state`]).

use subtle::ConstantTimeEq;

use crate::error::NoiseError;

/// Length of a ChaChaPoly / AESGCM authentication tag.
pub const TAG_LEN: usize = 16;
/// Length of an AEAD symmetric key.
pub const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Algorithm identifiers
// ---------------------------------------------------------------------------

/// Which DH function is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhKind {
    /// Curve25519 (32-byte keys, 32-byte DH output).
    X25519,
    /// Curve448 (56-byte keys, 56-byte DH output).
    X448,
}

impl DhKind {
    /// Returns the public key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            DhKind::X25519 => 32,
            DhKind::X448 => 56,
        }
    }

    /// Returns the protocol-name section of this DH function.
    pub fn name(self) -> &'static str {
        match self {
            DhKind::X25519 => "25519",
            DhKind::X448 => "448",
        }
    }

    /// Parses the protocol-name section of a DH function.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "25519" => Some(DhKind::X25519),
            "448" => Some(DhKind::X448),
            _ => None,
        }
    }
}

/// Which AEAD cipher is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    /// ChaCha20-Poly1305.
    ChaChaPoly,
    /// AES-256-GCM.
    AesGcm,
}

impl CipherKind {
    /// Returns the protocol-name section of this cipher.
    pub fn name(self) -> &'static str {
        match self {
            CipherKind::ChaChaPoly => "ChaChaPoly",
            CipherKind::AesGcm => "AESGCM",
        }
    }

    /// Parses the protocol-name section of a cipher.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ChaChaPoly" => Some(CipherKind::ChaChaPoly),
            "AESGCM" => Some(CipherKind::AesGcm),
            _ => None,
        }
    }
}

/// Which hash function is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    /// BLAKE2s with a 256-bit output.
    Blake2s,
    /// SHA-256.
    Sha256,
    /// BLAKE2b with a 512-bit output.
    Blake2b,
    /// SHA-512.
    Sha512,
}

impl HashKind {
    /// Returns the protocol-name section of this hash.
    pub fn name(self) -> &'static str {
        match self {
            HashKind::Blake2s => "BLAKE2s",
            HashKind::Sha256 => "SHA256",
            HashKind::Blake2b => "BLAKE2b",
            HashKind::Sha512 => "SHA512",
        }
    }

    /// Parses the protocol-name section of a hash function.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "BLAKE2s" => Some(HashKind::Blake2s),
            "SHA256" => Some(HashKind::Sha256),
            "BLAKE2b" => Some(HashKind::Blake2b),
            "SHA512" => Some(HashKind::Sha512),
            _ => None,
        }
    }

    /// Returns the hash output (and chaining-key) length in bytes.
    pub fn hash_len(self) -> usize {
        match self {
            HashKind::Blake2s | HashKind::Sha256 => 32,
            HashKind::Blake2b | HashKind::Sha512 => 64,
        }
    }

    /// Returns the HMAC block length in bytes.
    fn block_len(self) -> usize {
        match self {
            HashKind::Blake2s | HashKind::Sha256 => 64,
            HashKind::Blake2b | HashKind::Sha512 => 128,
        }
    }
}

// ---------------------------------------------------------------------------
// Hash / HMAC / HKDF
// ---------------------------------------------------------------------------

use blake2::{Blake2b512, Blake2s256, Digest};
use sha2::{Sha256, Sha512};

/// Computes `HASH(data)` for the selected hash function.
pub fn hash(kind: HashKind, data: &[u8]) -> Vec<u8> {
    match kind {
        HashKind::Blake2s => Blake2s256::digest(data).to_vec(),
        HashKind::Sha256 => Sha256::digest(data).to_vec(),
        HashKind::Blake2b => Blake2b512::digest(data).to_vec(),
        HashKind::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// HMAC-HASH as required by Noise's HKDF (spec section 4.3).
fn hmac(kind: HashKind, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let block_len = kind.block_len();
    let hash_len = kind.hash_len();

    let mut key_block = vec![0u8; block_len];
    if key.len() > block_len {
        key_block[..hash_len].copy_from_slice(&hash(kind, key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(block_len + 64);
    inner.extend(key_block.iter().map(|b| b ^ 0x36));
    for part in parts {
        inner.extend_from_slice(part);
    }
    let inner_hash = hash(kind, &inner);

    let mut outer = Vec::with_capacity(block_len + hash_len);
    outer.extend(key_block.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    hash(kind, &outer)
}

/// Noise's `HKDF(chaining_key, input_key_material, num_outputs)` from spec
/// section 4.3:
///
/// ```text
/// temp_key = HMAC-HASH(chaining_key, input_key_material)
/// output1  = HMAC-HASH(temp_key, 0x01)
/// output2  = HMAC-HASH(temp_key, output1 || 0x02)
/// ...
/// ```
///
/// Each output is `HASHLEN` bytes.
pub fn hkdf(kind: HashKind, chaining_key: &[u8], ikm: &[u8], num_outputs: u8) -> Vec<Vec<u8>> {
    assert!(
        (1..=3).contains(&num_outputs),
        "HKDF output count must be 1..=3"
    );
    let temp_key = hmac(kind, chaining_key, &[ikm]);

    let mut outputs = Vec::with_capacity(num_outputs as usize);
    let mut prev: Vec<u8> = Vec::new();
    for i in 1..=num_outputs {
        let counter = [i];
        prev = hmac(kind, &temp_key, &[&prev, &counter]);
        outputs.push(prev.clone());
    }
    outputs
}

// ---------------------------------------------------------------------------
// DH
// ---------------------------------------------------------------------------

/// A DH public key. Length depends on [`DhKind`].
#[derive(Clone, Debug)]
pub struct PublicKey {
    kind: DhKind,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Imports a public key, validating its length and rejecting low-order
    /// points (an all-zero / non-contributory key would be a security hole).
    pub fn from_bytes(kind: DhKind, bytes: &[u8]) -> Result<Self, NoiseError> {
        if bytes.len() != kind.key_len() {
            return Err(NoiseError::InvalidKeyLength {
                expected: kind.key_len(),
                got: bytes.len(),
            });
        }
        match kind {
            DhKind::X25519 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(bytes);
                let pk = x25519_dalek::PublicKey::from(arr);
                if pk.as_bytes().iter().all(|b| *b == 0) {
                    return Err(NoiseError::InvalidPublicKey("all-zero X25519 point"));
                }
            }
            DhKind::X448 => {
                // The x448 crate's checked constructor rejects low-order points.
                x448::PublicKey::from_bytes(bytes)
                    .ok_or(NoiseError::InvalidPublicKey("low-order X448 point"))?;
            }
        }
        Ok(PublicKey {
            kind,
            bytes: bytes.to_vec(),
        })
    }

    /// Returns the raw public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the DH kind of this key.
    pub fn kind(&self) -> DhKind {
        self.kind
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &PublicKey) -> bool {
        self.kind == other.kind && bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for PublicKey {}

/// A DH key pair; secret material is zeroized on drop.
#[derive(Clone)]
pub struct KeyPair {
    kind: DhKind,
    secret: zeroize::Zeroizing<Vec<u8>>,
    public: PublicKey,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secret material.
        f.debug_struct("KeyPair")
            .field("kind", &self.kind)
            .field("public", &hex::encode(&self.public.bytes))
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Derives the public key from a raw secret key. Clamping is performed by
    /// the underlying library exactly as the Noise DH functions specify.
    pub fn from_secret(kind: DhKind, secret: &[u8]) -> Result<Self, NoiseError> {
        if secret.len() != kind.key_len() {
            return Err(NoiseError::InvalidKeyLength {
                expected: kind.key_len(),
                got: secret.len(),
            });
        }
        let public = match kind {
            DhKind::X25519 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(secret);
                let sk = x25519_dalek::StaticSecret::from(arr);
                x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec()
            }
            DhKind::X448 => {
                let mut arr = [0u8; 56];
                arr.copy_from_slice(secret);
                let sk = x448::StaticSecret::from(arr);
                x448::PublicKey::from(&sk).as_bytes().to_vec()
            }
        };
        Ok(KeyPair {
            kind,
            secret: zeroize::Zeroizing::new(secret.to_vec()),
            public: PublicKey {
                kind,
                bytes: public,
            },
        })
    }

    /// Generates a fresh key pair from OS randomness.
    pub fn generate(kind: DhKind) -> Result<Self, NoiseError> {
        let mut secret = vec![0u8; kind.key_len()];
        getrandom::getrandom(&mut secret).map_err(|_| NoiseError::RandomnessUnavailable)?;
        let pair = Self::from_secret(kind, &secret)?;
        zeroize::Zeroize::zeroize(&mut secret);
        Ok(pair)
    }

    /// Returns the public half.
    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Returns the raw secret bytes. Use with care.
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Performs `DH(secret, public_key)` and returns the full DH output
    /// (`DHLEN` bytes), which is what `MixKey` consumes.
    pub fn diffie_hellman(&self, remote: &PublicKey) -> Result<Vec<u8>, NoiseError> {
        if remote.kind != self.kind {
            return Err(NoiseError::InvalidState("DH kind mismatch"));
        }
        match self.kind {
            DhKind::X25519 => {
                let mut sb = [0u8; 32];
                sb.copy_from_slice(&self.secret);
                let mut pb = [0u8; 32];
                pb.copy_from_slice(remote.as_bytes());
                let sk = x25519_dalek::StaticSecret::from(sb);
                let pk = x25519_dalek::PublicKey::from(pb);
                let shared = sk.diffie_hellman(&pk);
                if !shared.was_contributory() {
                    return Err(NoiseError::InvalidPublicKey("non-contributory X25519 DH"));
                }
                Ok(shared.to_bytes().to_vec())
            }
            DhKind::X448 => {
                let mut sb = [0u8; 56];
                sb.copy_from_slice(&self.secret);
                let sk = x448::StaticSecret::from(sb);
                let pk = x448::PublicKey::from_bytes(remote.as_bytes())
                    .ok_or(NoiseError::InvalidPublicKey("low-order X448 point"))?;
                Ok(sk.diffie_hellman(&pk).as_bytes().to_vec())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

/// Builds the 12-byte AEAD nonce.
///
/// * ChaChaPoly: 32 bits of zeros followed by little-endian `n` (spec 12.3).
/// * AESGCM: 32 bits of zeros followed by big-endian `n` (spec 12.4).
fn nonce_bytes(kind: CipherKind, n: u64) -> [u8; 12] {
    let mut out = [0u8; 12];
    let encoded = match kind {
        CipherKind::ChaChaPoly => n.to_le_bytes(),
        CipherKind::AesGcm => n.to_be_bytes(),
    };
    out[4..].copy_from_slice(&encoded);
    out
}

/// AEAD encryption. Returns ciphertext with the 16-byte tag appended.
pub fn aead_encrypt(
    kind: CipherKind,
    key: &[u8; KEY_LEN],
    nonce: u64,
    ad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = nonce_bytes(kind, nonce);
    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };
    match kind {
        CipherKind::ChaChaPoly => ChaCha20Poly1305::new(key.into())
            .encrypt(&nonce.into(), payload)
            .expect("AEAD encryption cannot fail for valid inputs"),
        CipherKind::AesGcm => Aes256Gcm::new(key.into())
            .encrypt(&nonce.into(), payload)
            .expect("AEAD encryption cannot fail for valid inputs"),
    }
}

/// AEAD decryption. `ciphertext` includes the 16-byte tag.
pub fn aead_decrypt(
    kind: CipherKind,
    key: &[u8; KEY_LEN],
    nonce: u64,
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    if ciphertext.len() < TAG_LEN {
        return Err(NoiseError::DecryptionFailed("ciphertext shorter than tag"));
    }
    let nonce = nonce_bytes(kind, nonce);
    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };
    let result = match kind {
        CipherKind::ChaChaPoly => ChaCha20Poly1305::new(key.into()).decrypt(&nonce.into(), payload),
        CipherKind::AesGcm => Aes256Gcm::new(key.into()).decrypt(&nonce.into(), payload),
    };
    result.map_err(|_| NoiseError::DecryptionFailed("AEAD tag mismatch"))
}

/// The `REKEY(k)` function from spec section 11.3:
///
/// ```text
/// REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32])[0..32]
/// ```
///
/// The reserved "max nonce" is used here deliberately (it is the only place
/// where that value is allowed, and it never advances the caller's nonce).
pub fn rekey(kind: CipherKind, key: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let ct = aead_encrypt(kind, key, u64::MAX, &[], &[0u8; KEY_LEN]);
    let mut new_key = [0u8; KEY_LEN];
    new_key.copy_from_slice(&ct[..KEY_LEN]);
    new_key
}

/// Constant-time equality for tags / test comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
