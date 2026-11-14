//! A from-scratch implementation of the [Noise Protocol Framework].
//!
//! The crate focuses on correctness and auditability over feature breadth:
//!
//! * Handshake patterns: `XX` and `IK` are the primary, first-class patterns;
//!   the full set of cacophony test-vector patterns is also available through
//!   [`patterns`] so the implementation can be checked against the official
//!   vector file.
//! * DH: X25519. X448 is available for vector cross-checking.
//! * Cipher: ChaCha20-Poly1305 and AES-256-GCM.
//! * Hash: BLAKE2s and SHA-256 (BLAKE2b / SHA-512 for vector cross-checking).
//! * Strict state machine: wrong-direction, out-of-order and replayed messages
//!   are rejected; see [`handshake`].
//! * Transport: sequential or explicit nonces, rekeying, nonce exhaustion and
//!   a replay window; see [`transport`].
//! * Full, structured tracing of every message and key derivation; see
//!   [`trace`].
//!
//! # Example
//!
//! ```
//! use noise_rs::{
//!     DhKind, HandshakeConfig, HandshakeState, KeyPair, ProtocolParams, Role, TraceMode,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let params = ProtocolParams::parse("Noise_XX_25519_ChaChaPoly_BLAKE2s")?;
//! let mut initiator = HandshakeState::new(
//!     params.clone(),
//!     Role::Initiator,
//!     HandshakeConfig {
//!         local_static: Some(KeyPair::generate(DhKind::X25519)?),
//!         prologue: b"prologue".to_vec(),
//!         ..Default::default()
//!     },
//!     TraceMode::Off,
//! )?;
//! let mut responder = HandshakeState::new(
//!     params,
//!     Role::Responder,
//!     HandshakeConfig {
//!         local_static: Some(KeyPair::generate(DhKind::X25519)?),
//!         prologue: b"prologue".to_vec(),
//!         ..Default::default()
//!     },
//!     TraceMode::Off,
//! )?;
//!
//! // XX has three messages: -> e ; <- e, ee, s, es ; -> s, se
//! let m0 = initiator.write_message(b"")?;
//! responder.read_message(&m0.bytes)?;
//! let m1 = responder.write_message(b"")?;
//! initiator.read_message(&m1.bytes)?;
//! let m2 = initiator.write_message(b"")?;
//! responder.read_message(&m2.bytes)?;
//!
//! let mut initiator_transport = initiator.into_transport()?;
//! let mut responder_transport = responder.into_transport()?;
//! let ciphertext = initiator_transport.send(b"hello")?;
//! assert_eq!(responder_transport.receive(&ciphertext)?, b"hello");
//! # Ok(())
//! # }
//! ```
//!
//! [Noise Protocol Framework]: https://noiseprotocol.org/noise.html

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod params;
pub mod patterns;
pub mod symmetric;
pub mod trace;
pub mod trace_sink;
pub mod transport;
pub mod vectors;

pub use crypto::{CipherKind, DhKind, HashKind, KeyPair, PublicKey};
pub use error::NoiseError;
pub use handshake::{
    HandshakeConfig, HandshakeMessage, HandshakeState, ReceivedMessage, MAX_MESSAGE_LEN,
};
pub use params::ProtocolParams;
pub use patterns::{Pattern, Role, Token};
pub use trace::{Secret, TraceEvent, TraceLog, TraceMode};
pub use trace_sink::TraceSink;
pub use transport::{ReplayWindow, TransportState};
