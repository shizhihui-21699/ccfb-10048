//! The transport phase: post-handshake AEAD messages, rekeying, nonce
//! exhaustion and replay protection.
//!
//! Two modes are supported:
//!
//! * **Sequential** ([`TransportState::send`] / [`TransportState::receive`]):
//!   each party has a 64-bit nonce that increments with every message, exactly
//!   as section 5.1 describes. Because the nonce is implicit, a replayed or
//!   out-of-order ciphertext fails AEAD authentication: the receiver will use
//!   a different nonce than the sender and the associated data/tag check fails.
//!
//! * **Explicit nonce** ([`TransportState::send_with_nonce`] /
//!   [`TransportState::receive_with_nonce`]): for lossy or out-of-order links
//!   (section 11.4). The caller transmits the nonce next to the ciphertext.
//!   The receiver tracks successfully decrypted nonces in a sliding replay
//!   window and rejects duplicates, so a captured message cannot be replayed.
//!
//! Nonce exhaustion ([`NoiseError::NonceExhausted`]): the maximum nonce
//! `2^64-1` is reserved by the specification. Once a cipher state reaches it,
//! every further operation fails; the application must run a new handshake.
//! `rekey()` rotates the key but deliberately keeps the nonce counter, so
//! rekeying does **not** buy extra messages.

use std::collections::VecDeque;

use crate::crypto::{CipherKind, KEY_LEN};
use crate::error::NoiseError;
use crate::patterns::Role;
use crate::symmetric::CipherState;
use crate::trace::{TraceEvent, TraceLog, TraceMode};

use crate::handshake::MAX_MESSAGE_LEN;

/// How many recently seen explicit nonces are remembered for replay checks.
const REPLAY_WINDOW: u64 = 1024;

/// A sliding-window replay filter for explicit-nonce transport messages.
///
/// The window is anchored at the highest nonce that has been successfully
/// authenticated: `seen[i]` records whether nonce `highest - i` has been seen,
/// for `i` in `0..REPLAY_WINDOW`. A nonce above `highest` is always fresh; a
/// nonce within the window is fresh only if its bit is clear; anything older
/// than the window is refused (it could otherwise be replayed after the bit
/// has been recycled).
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    seen: VecDeque<bool>,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// Creates an empty window.
    pub fn new() -> Self {
        ReplayWindow {
            highest: None,
            seen: VecDeque::new(),
        }
    }

    /// Checks whether `nonce` may still be accepted, without recording it.
    pub fn is_fresh(&self, nonce: u64) -> bool {
        match self.highest {
            None => true,
            Some(high) if nonce > high => true,
            Some(high) => {
                let offset = (high - nonce) as usize;
                offset < self.seen.len() && !self.seen[offset]
            }
        }
    }

    /// Records a successfully authenticated nonce.
    pub fn record(&mut self, nonce: u64) {
        match self.highest {
            None => {
                self.seen = VecDeque::from(vec![false; REPLAY_WINDOW as usize]);
                self.seen[0] = true;
                self.highest = Some(nonce);
            }
            Some(high) if nonce > high => {
                let advance = (nonce - high) as usize;
                if advance >= REPLAY_WINDOW as usize {
                    for bit in self.seen.iter_mut() {
                        *bit = false;
                    }
                } else {
                    for _ in 0..advance {
                        self.seen.push_front(false);
                    }
                    self.seen.truncate(REPLAY_WINDOW as usize);
                }
                self.seen[0] = true;
                self.highest = Some(nonce);
            }
            Some(high) => {
                let offset = (high - nonce) as usize;
                if offset < self.seen.len() {
                    self.seen[offset] = true;
                }
            }
        }
    }
}

/// The post-handshake transport state for one party.
#[derive(Debug)]
pub struct TransportState {
    role: Role,
    cipher: CipherKind,
    sending: CipherState,
    receiving: CipherState,
    handshake_hash: Vec<u8>,
    replay: ReplayWindow,
    trace: TraceLog,
}

impl TransportState {
    pub(crate) fn new(
        role: Role,
        cipher: CipherKind,
        sending: CipherState,
        receiving: CipherState,
        handshake_hash: Vec<u8>,
        trace: TraceLog,
    ) -> Self {
        TransportState {
            role,
            cipher,
            sending,
            receiving,
            handshake_hash,
            replay: ReplayWindow::new(),
            trace,
        }
    }

    /// Creates a transport state directly from raw split keys.
    ///
    /// `sending` must already be selected for this party's direction. This is
    /// meant for resuming a session; normally you obtain a `TransportState`
    /// from [`crate::HandshakeState::into_transport`].
    pub fn from_keys(
        role: Role,
        cipher: CipherKind,
        sending_key: [u8; KEY_LEN],
        receiving_key: [u8; KEY_LEN],
        handshake_hash: Vec<u8>,
        trace_mode: TraceMode,
    ) -> Self {
        TransportState {
            role,
            cipher,
            sending: CipherState::initialize_key(cipher, sending_key),
            receiving: CipherState::initialize_key(cipher, receiving_key),
            handshake_hash,
            replay: ReplayWindow::new(),
            trace: TraceLog::new(trace_mode),
        }
    }

    /// This party's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The channel-binding handshake hash.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.handshake_hash
    }

    /// The cipher in use.
    pub fn cipher(&self) -> CipherKind {
        self.cipher
    }

    /// The next nonce that will be used for sending.
    pub fn sending_nonce(&self) -> u64 {
        self.sending.nonce()
    }

    /// The next nonce that would be used for implicit-nonce receiving.
    pub fn receiving_nonce(&self) -> u64 {
        self.receiving.nonce()
    }

    /// Drains trace events.
    pub fn take_trace(&mut self) -> Vec<TraceEvent> {
        self.trace.take()
    }

    /// Whether `nonce` would still be accepted by the replay window.
    ///
    /// Exposed for tests and for applications that want to pre-check a frame
    /// without attempting decryption.
    pub fn replay_window_is_fresh(&self, nonce: u64) -> bool {
        self.replay.is_fresh(nonce)
    }

    /// Copies the current sending key. Debugging and test use only: handling
    /// raw key material outside the state machine defeats its protections.
    pub fn export_sending_key(&self) -> [u8; KEY_LEN] {
        *self
            .sending
            .key()
            .expect("transport states always have keys")
    }

    /// Copies the current receiving key. Same warning as
    /// [`TransportState::export_sending_key`].
    pub fn export_receiving_key(&self) -> [u8; KEY_LEN] {
        *self
            .receiving
            .key()
            .expect("transport states always have keys")
    }

    /// Sets the sending nonce explicitly (spec section 5.1 `SetNonce`).
    ///
    /// Intended for session resumption and for tests that exercise nonce
    /// exhaustion; the caller must never reuse a nonce with the same key.
    pub fn set_sending_nonce(&mut self, nonce: u64) -> Result<(), NoiseError> {
        self.sending.set_nonce(nonce)
    }

    /// Sets the receiving nonce explicitly (spec section 5.1 `SetNonce`).
    ///
    /// Replay protection for explicit nonces is handled by
    /// [`TransportState::receive_with_nonce`]; this setter is for resumption.
    pub fn set_receiving_nonce(&mut self, nonce: u64) -> Result<(), NoiseError> {
        self.receiving.set_nonce(nonce)
    }

    /// Encrypts a transport message using the next sequential nonce.
    ///
    /// Fails with [`NoiseError::NonceExhausted`] once the counter reaches the
    /// reserved maximum value.
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if payload.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: payload.len(),
            });
        }
        let nonce = self.sending.nonce();
        let key = self
            .trace
            .secret(self.sending.key().map(|k| &k[..]).unwrap_or(&[]));
        let ct = match self.sending.encrypt_with_ad(&[], payload) {
            Ok(ct) => ct,
            Err(err) => {
                self.trace.push(TraceEvent::Rejected {
                    operation: "transport send",
                    reason: err.to_string(),
                });
                return Err(err);
            }
        };
        self.trace.push(TraceEvent::TransportSend {
            nonce,
            key,
            plaintext_len: payload.len(),
            bytes: hex::encode(&ct),
        });
        Ok(ct)
    }

    /// Decrypts a transport message using the next sequential nonce.
    ///
    /// A replayed or reordered message fails authentication because the nonce
    /// no longer matches. A failed decryption does not advance the receiver's
    /// nonce, so a valid successor can still be processed.
    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: ciphertext.len(),
            });
        }
        let nonce = self.receiving.nonce();
        let key = self
            .trace
            .secret(self.receiving.key().map(|k| &k[..]).unwrap_or(&[]));
        let plaintext = match self.receiving.decrypt_with_ad(&[], ciphertext) {
            Ok(pt) => pt,
            Err(err) => {
                self.trace.push(TraceEvent::TransportReceive {
                    nonce: Some(nonce),
                    key,
                    ciphertext_len: ciphertext.len(),
                    plaintext_len: None,
                    ok: false,
                    explicit: false,
                });
                self.trace.push(TraceEvent::Rejected {
                    operation: "transport receive",
                    reason: err.to_string(),
                });
                return Err(err);
            }
        };
        self.trace.push(TraceEvent::TransportReceive {
            nonce: Some(nonce),
            key,
            ciphertext_len: ciphertext.len(),
            plaintext_len: Some(plaintext.len()),
            ok: true,
            explicit: false,
        });
        Ok(plaintext)
    }

    /// Encrypts a message under an explicit nonce (out-of-order transport).
    ///
    /// The application must transmit the nonce alongside the ciphertext.
    /// Nonces must never repeat for the same key.
    pub fn send_with_nonce(&mut self, nonce: u64, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if payload.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: payload.len(),
            });
        }
        self.sending.set_nonce(nonce)?;
        let key = self
            .trace
            .secret(self.sending.key().map(|k| &k[..]).unwrap_or(&[]));
        let ct = self.sending.encrypt_with_ad(&[], payload)?;
        self.trace.push(TraceEvent::TransportSend {
            nonce,
            key,
            plaintext_len: payload.len(),
            bytes: hex::encode(&ct),
        });
        Ok(ct)
    }

    /// Decrypts a message under an explicit nonce, with replay protection.
    ///
    /// A nonce that has already been used successfully, or that falls outside
    /// the replay window, is rejected with [`NoiseError::ReplayDetected`]
    /// before any decryption is attempted.
    pub fn receive_with_nonce(
        &mut self,
        nonce: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.replay.is_fresh(nonce) {
            self.trace.push(TraceEvent::Rejected {
                operation: "transport receive (explicit nonce)",
                reason: format!("replayed nonce {nonce}"),
            });
            return Err(NoiseError::ReplayDetected);
        }
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: ciphertext.len(),
            });
        }
        self.receiving.set_nonce(nonce)?;
        let key = self
            .trace
            .secret(self.receiving.key().map(|k| &k[..]).unwrap_or(&[]));
        let plaintext = match self.receiving.decrypt_with_ad(&[], ciphertext) {
            Ok(pt) => pt,
            Err(err) => {
                self.trace.push(TraceEvent::TransportReceive {
                    nonce: Some(nonce),
                    key,
                    ciphertext_len: ciphertext.len(),
                    plaintext_len: None,
                    ok: false,
                    explicit: true,
                });
                return Err(err);
            }
        };
        self.replay.record(nonce);
        self.trace.push(TraceEvent::TransportReceive {
            nonce: Some(nonce),
            key,
            ciphertext_len: ciphertext.len(),
            plaintext_len: Some(plaintext.len()),
            ok: true,
            explicit: true,
        });
        Ok(plaintext)
    }

    /// Rotates the sending key (section 11.3). The nonce is preserved.
    pub fn rekey_sending(&mut self) {
        let nonce = self.sending.nonce();
        if let Some(old) = self.sending.rekey() {
            let new = *self.sending.key().expect("key exists after rekey");
            self.trace.push(TraceEvent::Rekey {
                direction: "send",
                nonce,
                old_key: self.trace.secret(&old),
                new_key: self.trace.secret(&new),
            });
        }
    }

    /// Rotates the receiving key (section 11.3). The nonce is preserved.
    ///
    /// Both parties must rekey in lockstep for traffic to remain readable.
    pub fn rekey_receiving(&mut self) {
        let nonce = self.receiving.nonce();
        if let Some(old) = self.receiving.rekey() {
            let new = *self.receiving.key().expect("key exists after rekey");
            self.trace.push(TraceEvent::Rekey {
                direction: "receive",
                nonce,
                old_key: self.trace.secret(&old),
                new_key: self.trace.secret(&new),
            });
        }
    }
}
