//! Error type shared by the whole Noise implementation.
//!
//! Every public operation returns [`NoiseError`]; the error variants are
//! deliberately explicit so a caller can distinguish *why* a message was
//! rejected (wrong direction, replay, bad tag, nonce exhaustion, ...).

use std::fmt;

/// Errors produced by the Noise state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoiseError {
    /// The protocol name could not be parsed.
    InvalidProtocolName(String),
    /// A handshake pattern / primitive is not known to this implementation.
    UnsupportedAlgorithm(String),
    /// A key had the wrong length for the selected DH function.
    InvalidKeyLength { expected: usize, got: usize },
    /// A key required by the pattern was not supplied.
    MissingKey(&'static str),
    /// A `psk` token was reached but no pre-shared key was configured.
    PskRequired,
    /// A PSK was supplied for a pattern that does not use one.
    PskNotAllowed,
    /// The caller tried to write a message that belongs to the other party.
    WrongRole { expected: &'static str },
    /// The handshake is already complete; use the transport state.
    HandshakeComplete,
    /// The handshake has not completed yet.
    HandshakeIncomplete,
    /// A message was shorter than the tokens in the pattern require.
    MessageTooShort { needed: usize, got: usize },
    /// A message exceeded the configured maximum length.
    MessageTooLong { max: usize, got: usize },
    /// AEAD authentication failed.
    DecryptionFailed(&'static str),
    /// A public key was structurally invalid (wrong length or low order).
    InvalidPublicKey(&'static str),
    /// The pattern tried to set a remote static key that was already known.
    UnexpectedStaticKey,
    /// A previously processed handshake message was presented again.
    ReplayDetected,
    /// The 64-bit nonce reached the reserved maximum value.
    NonceExhausted,
    /// Randomness generation failed.
    RandomnessUnavailable,
    /// The request is not available on this half of a split transport.
    NotAvailable(&'static str),
    /// An invariant expected by the implementation was violated.
    InvalidState(&'static str),
}

impl fmt::Display for NoiseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoiseError::InvalidProtocolName(n) => write!(f, "invalid Noise protocol name: {n}"),
            NoiseError::UnsupportedAlgorithm(n) => write!(f, "unsupported algorithm: {n}"),
            NoiseError::InvalidKeyLength { expected, got } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {got}"
                )
            }
            NoiseError::MissingKey(k) => write!(f, "required key not set: {k}"),
            NoiseError::PskRequired => write!(f, "the handshake pattern requires a pre-shared key"),
            NoiseError::PskNotAllowed => {
                write!(f, "a pre-shared key was supplied for a non-PSK pattern")
            }
            NoiseError::WrongRole { expected } => {
                write!(
                    f,
                    "wrong message direction: this message must be sent by the {expected}"
                )
            }
            NoiseError::HandshakeComplete => {
                write!(f, "handshake is complete; use the transport state")
            }
            NoiseError::HandshakeIncomplete => write!(f, "handshake is not complete"),
            NoiseError::MessageTooShort { needed, got } => {
                write!(
                    f,
                    "message too short: need at least {needed} bytes, got {got}"
                )
            }
            NoiseError::MessageTooLong { max, got } => {
                write!(f, "message too long: limit is {max} bytes, got {got}")
            }
            NoiseError::DecryptionFailed(where_) => {
                write!(f, "authentication failed while decrypting ({where_})")
            }
            NoiseError::InvalidPublicKey(why) => write!(f, "invalid public key: {why}"),
            NoiseError::UnexpectedStaticKey => {
                write!(
                    f,
                    "remote static key already known; refusing to overwrite it"
                )
            }
            NoiseError::ReplayDetected => write!(f, "replayed handshake message rejected"),
            NoiseError::NonceExhausted => write!(
                f,
                "nonce exhausted (2^64-1 is reserved); a new handshake is required"
            ),
            NoiseError::RandomnessUnavailable => write!(f, "OS randomness is unavailable"),
            NoiseError::NotAvailable(what) => write!(f, "not available: {what}"),
            NoiseError::InvalidState(what) => write!(f, "invalid state: {what}"),
        }
    }
}

impl std::error::Error for NoiseError {}
