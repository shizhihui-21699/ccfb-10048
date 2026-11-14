//! Structured tracing of the handshake and transport phases.
//!
//! The library never prints anything by itself. Instead every operation appends
//! [`TraceEvent`]s to a [`TraceLog`] which the application (the `noise-cli`
//! binary, or a test) can drain and render. This makes the exact sequence of
//! messages, token processing, hash/key derivations and AEAD operations
//! observable without compromising the normal API.
//!
//! Key material is *redacted by default*: only a short fingerprint is emitted.
//! Use [`TraceMode::Full`] (CLI: `--reveal-secrets`) when debugging locally and
//! you explicitly want raw key bytes, e.g. to compare against a test vector.

use crate::crypto::{hash, HashKind};
use crate::patterns::{Role, Token};

/// How much detail a trace log records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TraceMode {
    /// Record nothing.
    #[default]
    Off,
    /// Record events, but replace secret bytes with fingerprints.
    Redacted,
    /// Record events including raw secret bytes.
    Full,
}

/// A printable piece of key material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Secret {
    /// Not recorded.
    Omitted,
    /// A truncated, non-reversible fingerprint, safe to log.
    Fingerprint(String),
    /// The raw value, hex-encoded (only with [`TraceMode::Full`]).
    Full(String),
}

impl Secret {
    /// Renders the value for display.
    pub fn as_str(&self) -> &str {
        match self {
            Secret::Omitted => "<omitted>",
            Secret::Fingerprint(s) | Secret::Full(s) => s,
        }
    }

    /// True when raw bytes are included.
    pub fn is_full(&self) -> bool {
        matches!(self, Secret::Full(_))
    }
}

/// A single observable step of the protocol.
#[derive(Clone, Debug)]
pub enum TraceEvent {
    /// The handshake state was initialized.
    Init {
        /// Canonical protocol name, e.g. `Noise_XX_25519_ChaChaPoly_BLAKE2s`.
        protocol_name: String,
        /// This party's role.
        role: Role,
        /// Whether the pattern is PSK based.
        psk_mode: bool,
        /// Prologue bytes (hex).
        prologue: String,
        /// `h` after mixing the prologue.
        h: String,
        /// `ck` after mixing the prologue.
        ck: Secret,
    },
    /// A pre-message token was mixed in.
    PreMessage {
        /// Which side contributed the pre-message key.
        sender: Role,
        /// The token (`e` or `s`).
        token: Token,
        /// The public key (hex).
        public_key: String,
        /// `h` after mixing.
        h: String,
    },
    /// A handshake message was written or read.
    Message {
        /// Zero-based message index.
        index: usize,
        /// Which party sends this message.
        sender: Role,
        /// `"write"` or `"read"`.
        direction: &'static str,
        /// Length of the payload carried.
        payload_len: usize,
        /// Total wire length in bytes.
        wire_len: usize,
        /// The complete wire message (hex).
        wire: String,
    },
    /// A handshake token was processed.
    Token {
        /// Message index this token belongs to.
        index: usize,
        /// The token itself.
        token: Token,
        /// Key/value details (public keys, DH results, ...).
        details: Vec<(&'static str, String)>,
        /// `h` after the token.
        h: String,
        /// `ck` after the token.
        ck: Secret,
        /// Whether an encryption key is now installed.
        has_key: bool,
        /// The current nonce of the message's cipher state.
        nonce: u64,
    },
    /// The handshake payload was encrypted or decrypted.
    Payload {
        /// Message index.
        index: usize,
        /// `"encrypt"` or `"decrypt"`.
        direction: &'static str,
        /// Nonce used (absent when no key was established yet).
        nonce: Option<u64>,
        /// AEAD associated data (the current `h`).
        ad: String,
        /// The AEAD key, redacted unless [`TraceMode::Full`].
        key: Secret,
        /// Length before the operation.
        input_len: usize,
        /// Length after the operation.
        output_len: usize,
        /// The resulting ciphertext (hex).
        bytes: String,
        /// Whether decryption authenticated successfully.
        ok: bool,
        /// `h` after mixing the ciphertext.
        h_after: String,
    },
    /// The handshake completed and transport keys were derived.
    Split {
        /// The final handshake hash.
        handshake_hash: String,
        /// Key for initiator-to-responder messages.
        k1: Secret,
        /// Key for responder-to-initiator messages.
        k2: Secret,
        /// Which key this party will use for sending.
        sending_key: Secret,
        /// Which key this party will use for receiving.
        receiving_key: Secret,
    },
    /// A transport message was encrypted.
    TransportSend {
        /// Nonce used.
        nonce: u64,
        /// AEAD key, redacted unless [`TraceMode::Full`].
        key: Secret,
        /// Plaintext length.
        plaintext_len: usize,
        /// Ciphertext bytes (tag included, hex).
        bytes: String,
    },
    /// A transport message was decrypted.
    TransportReceive {
        /// Nonce used; `None` when using the implicit sequential nonce.
        nonce: Option<u64>,
        /// AEAD key, redacted unless [`TraceMode::Full`].
        key: Secret,
        /// Ciphertext length.
        ciphertext_len: usize,
        /// Plaintext length on success.
        plaintext_len: Option<usize>,
        /// Whether decryption authenticated successfully.
        ok: bool,
        /// Whether the caller supplied an explicit nonce.
        explicit: bool,
    },
    /// An AEAD key was rotated.
    Rekey {
        /// `"send"` or `"receive"`.
        direction: &'static str,
        /// The nonce counter (unchanged by rekeying).
        nonce: u64,
        /// Previous key.
        old_key: Secret,
        /// Replacement key.
        new_key: Secret,
    },
    /// A request was rejected; includes the reason.
    Rejected {
        /// Operation that was rejected.
        operation: &'static str,
        /// Human-readable reason.
        reason: String,
    },
}

/// A buffer of trace events plus the policy for showing secrets.
#[derive(Debug)]
pub struct TraceLog {
    mode: TraceMode,
    events: Vec<TraceEvent>,
}

impl Default for TraceLog {
    fn default() -> Self {
        TraceLog {
            mode: TraceMode::Off,
            events: Vec::new(),
        }
    }
}

impl TraceLog {
    /// Creates a log with the given mode.
    pub fn new(mode: TraceMode) -> Self {
        TraceLog {
            mode,
            events: Vec::new(),
        }
    }

    /// Creates a log that records raw secret bytes.
    pub fn with_reveal_secrets() -> Self {
        TraceLog {
            mode: TraceMode::Full,
            events: Vec::new(),
        }
    }

    /// The current mode.
    pub fn mode(&self) -> TraceMode {
        self.mode
    }

    /// Whether any event is being recorded.
    pub fn is_on(&self) -> bool {
        self.mode != TraceMode::Off
    }

    /// Whether raw secrets are revealed.
    pub fn reveals_secrets(&self) -> bool {
        self.mode == TraceMode::Full
    }

    /// Records an event (unless tracing is off).
    pub fn push(&mut self, event: TraceEvent) {
        if self.is_on() {
            self.events.push(event);
        }
    }

    /// Removes and returns all pending events.
    pub fn take(&mut self) -> Vec<TraceEvent> {
        std::mem::take(&mut self.events)
    }

    /// Renders `bytes` according to the secret policy.
    ///
    /// Redacted mode uses the first 8 bytes of SHA-256 over the value, so the
    /// same key can be correlated between steps without being revealed.
    pub fn secret(&self, bytes: &[u8]) -> Secret {
        match self.mode {
            TraceMode::Off => Secret::Omitted,
            TraceMode::Redacted => {
                let digest = hash(HashKind::Sha256, bytes);
                Secret::Fingerprint(hex::encode(&digest[..8]))
            }
            TraceMode::Full => Secret::Full(hex::encode(bytes)),
        }
    }
}
