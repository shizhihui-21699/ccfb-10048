//! The `CipherState` and `SymmetricState` objects from Noise sections 5.1-5.2.

use zeroize::Zeroize;

use crate::crypto::{
    self, aead_decrypt, aead_encrypt, hash, hkdf, CipherKind, HashKind, KEY_LEN, TAG_LEN,
};
use crate::error::NoiseError;

/// A `CipherState`: an optional 32-byte key plus a 64-bit nonce.
#[derive(Clone, Debug)]
pub struct CipherState {
    cipher: CipherKind,
    key: Option<[u8; KEY_LEN]>,
    n: u64,
}

impl Drop for CipherState {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_mut() {
            key.zeroize();
        }
    }
}

impl CipherState {
    /// Creates a keyless cipher state with `n = 0`.
    pub fn new(cipher: CipherKind) -> Self {
        CipherState {
            cipher,
            key: None,
            n: 0,
        }
    }

    /// Imports a key and resets `n` to zero (section 5.1 `InitializeKey`).
    pub fn initialize_key(cipher: CipherKind, key: [u8; KEY_LEN]) -> Self {
        CipherState {
            cipher,
            key: Some(key),
            n: 0,
        }
    }

    /// Returns true when a key has been established.
    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// The current nonce.
    pub fn nonce(&self) -> u64 {
        self.n
    }

    /// The AEAD key, if any (used for tracing only).
    pub(crate) fn key(&self) -> Option<&[u8; KEY_LEN]> {
        self.key.as_ref()
    }

    /// Sets the nonce explicitly (section 11.4: out-of-order transport).
    pub fn set_nonce(&mut self, n: u64) -> Result<(), NoiseError> {
        // 2^64-1 is reserved by the specification and may never be selected.
        if n == u64::MAX {
            return Err(NoiseError::NonceExhausted);
        }
        self.n = n;
        Ok(())
    }

    /// Returns true when the nonce may still be used for an AEAD operation.
    ///
    /// Section 5.1 reserves the maximum nonce `2^64-1`, so `n` may be used
    /// while it is at most `2^64-2`. Once `n` reaches `2^64-1`, every further
    /// call must fail -- that is the "nonce exhausted" condition this crate
    /// surfaces as [`NoiseError::NonceExhausted`].
    fn nonce_usable(&self) -> bool {
        self.n < u64::MAX
    }

    /// Advances the nonce.
    ///
    /// The call that *uses* `n = 2^64 - 2` still succeeds (its ciphertext is
    /// valid); it moves `n` to the reserved value `2^64 - 1`, after which
    /// [`CipherState::encrypt_with_ad`] / [`CipherState::decrypt_with_ad`]
    /// refuse to run. See spec section 5.1.
    fn advance_nonce(&mut self) {
        debug_assert!(self.n < u64::MAX);
        self.n += 1;
    }

    /// `EncryptWithAd(ad, plaintext)`.
    ///
    /// With no key this returns the plaintext unchanged; in both cases the
    /// nonce advances by one.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.nonce_usable() {
            return Err(NoiseError::NonceExhausted);
        }
        let result = match &self.key {
            Some(key) => aead_encrypt(self.cipher, key, self.n, ad, plaintext),
            None => plaintext.to_vec(),
        };
        self.advance_nonce();
        Ok(result)
    }

    /// `DecryptWithAd(ad, ciphertext)`.
    ///
    /// On authentication failure the nonce is *not* incremented (section 5.1).
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.nonce_usable() {
            return Err(NoiseError::NonceExhausted);
        }
        let result = match &self.key {
            Some(key) => aead_decrypt(self.cipher, key, self.n, ad, ciphertext)?,
            None => ciphertext.to_vec(),
        };
        self.advance_nonce();
        Ok(result)
    }

    /// `Rekey()` from section 11.3. Updates `k` only; `n` is preserved.
    ///
    /// Returns the previous key when one was installed.
    pub fn rekey(&mut self) -> Option<[u8; KEY_LEN]> {
        match self.key.as_mut() {
            Some(key) => {
                let old = *key;
                *key = crypto::rekey(self.cipher, key);
                Some(old)
            }
            None => None,
        }
    }

    /// The cipher in use.
    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }
}

/// A `SymmetricState`: a `CipherState` plus the chaining key `ck` and hash `h`.
#[derive(Clone, Debug)]
pub struct SymmetricState {
    cipher: CipherKind,
    hash: HashKind,
    ck: Vec<u8>,
    h: Vec<u8>,
    cipher_state: CipherState,
}

impl Drop for SymmetricState {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
    }
}

impl SymmetricState {
    /// `InitializeSymmetric(protocol_name)` from section 5.2.
    pub fn new(cipher: CipherKind, hash_kind: HashKind, protocol_name: &[u8]) -> Self {
        let hash_len = hash_kind.hash_len();
        let h = if protocol_name.len() <= hash_len {
            let mut v = vec![0u8; hash_len];
            v[..protocol_name.len()].copy_from_slice(protocol_name);
            v
        } else {
            hash(hash_kind, protocol_name)
        };
        let ck = h.clone();
        SymmetricState {
            cipher,
            hash: hash_kind,
            ck,
            h,
            cipher_state: CipherState::new(cipher),
        }
    }

    /// The current `h`.
    pub fn h(&self) -> &[u8] {
        &self.h
    }

    /// The current `ck`.
    pub fn ck(&self) -> &[u8] {
        &self.ck
    }

    /// The cipher state.
    pub fn cipher_state(&self) -> &CipherState {
        &self.cipher_state
    }

    /// The hash function in use.
    pub fn hash_kind(&self) -> HashKind {
        self.hash
    }

    /// `MixKey(input_key_material)`: `ck, temp_k = HKDF(ck, ikm, 2)`, then
    /// `InitializeKey(truncate(temp_k, 32))`.
    pub fn mix_key(&mut self, ikm: &[u8]) {
        let outputs = hkdf(self.hash, &self.ck, ikm, 2);
        self.ck = outputs[0].clone();
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&outputs[1][..KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(self.cipher, key);
    }

    /// `MixHash(data)`: `h = HASH(h || data)`.
    pub fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(self.h.len() + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = hash(self.hash, &buf);
    }

    /// `MixKeyAndHash(ikm)`: `ck, temp_h, temp_k = HKDF(ck, ikm, 3)`,
    /// `MixHash(temp_h)`, `InitializeKey(truncate(temp_k, 32))`.
    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let outputs = hkdf(self.hash, &self.ck, ikm, 3);
        self.ck = outputs[0].clone();
        let temp_h = outputs[1].clone();
        self.mix_hash(&temp_h);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&outputs[2][..KEY_LEN]);
        self.cipher_state = CipherState::initialize_key(self.cipher, key);
    }

    /// `EncryptAndHash(plaintext)`.
    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ad = self.h.clone();
        let ciphertext = self.cipher_state.encrypt_with_ad(&ad, plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// `DecryptAndHash(ciphertext)`.
    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ad = self.h.clone();
        let plaintext = self.cipher_state.decrypt_with_ad(&ad, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// `Split()`: derive the two transport cipher states.
    ///
    /// Returns `(c1, c2)` where `c1` encrypts initiator-to-responder traffic.
    pub fn split(&self) -> (CipherState, CipherState) {
        let outputs = hkdf(self.hash, &self.ck, &[], 2);
        let mut k1 = [0u8; KEY_LEN];
        let mut k2 = [0u8; KEY_LEN];
        k1.copy_from_slice(&outputs[0][..KEY_LEN]);
        k2.copy_from_slice(&outputs[1][..KEY_LEN]);
        (
            CipherState::initialize_key(self.cipher, k1),
            CipherState::initialize_key(self.cipher, k2),
        )
    }

    /// The AEAD tag length.
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The ciphertext length produced for `plaintext_len` bytes, given whether
    /// a key is currently established.
    pub fn ciphertext_len(&self, plaintext_len: usize) -> usize {
        if self.cipher_state.has_key() {
            plaintext_len + TAG_LEN
        } else {
            plaintext_len
        }
    }
}
