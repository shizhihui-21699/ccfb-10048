//! Loader and runner for the official cacophony test vector file.
//!
//! The file (`tests/vectors/cacophony.txt`, public domain, from
//! <https://github.com/mcginty/cacophony>) contains 576 vectors covering every
//! fundamental handshake pattern, all PSK variants, both DH functions, both
//! ciphers and all four hash functions.
//!
//! Each vector is a complete transcript: the prologue, both parties' static
//! and ephemeral keys, the ciphertext of every handshake message (and the
//! plaintext payload it carried), and the final handshake hash. Running the
//! vector means replaying the handshake with the fixed keys and comparing
//! every byte, which is the strongest available check of the state machine,
//! the HKDF/MixHash chaining and the AEAD nonce encodings.

use crate::crypto::{DhKind, KeyPair, PublicKey};
use crate::error::NoiseError;
use crate::handshake::{HandshakeConfig, HandshakeState};
use crate::params::ProtocolParams;
use crate::patterns::Role;
use crate::trace::TraceMode;
use crate::transport::TransportState;
use serde::Deserialize;

/// One handshake message inside a vector.
#[derive(Clone, Debug, Deserialize)]
pub struct VectorMessage {
    /// Hexadecimal plaintext payload.
    pub payload: String,
    /// Hexadecimal wire ciphertext (tag included).
    pub ciphertext: String,
}

/// One test vector.
#[derive(Clone, Debug, Deserialize)]
pub struct Vector {
    /// Optional human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Protocol name, e.g. `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
    pub protocol_name: String,
    /// Whether this vector is expected to fail.
    #[serde(default)]
    pub fail: bool,
    /// Initiator prologue (hex).
    #[serde(default)]
    pub init_prologue: String,
    /// Initiator PSK (hex).
    #[serde(default)]
    pub init_psk: Option<String>,
    /// Initiator ephemeral secret key (hex).
    #[serde(default)]
    pub init_ephemeral: Option<String>,
    /// Initiator static secret key (hex).
    #[serde(default)]
    pub init_static: Option<String>,
    /// The responder's static public key as known to the initiator (hex).
    #[serde(default)]
    pub init_remote_static: Option<String>,
    /// Responder prologue (hex).
    #[serde(default)]
    pub resp_prologue: String,
    /// Responder PSK (hex).
    #[serde(default)]
    pub resp_psk: Option<String>,
    /// Responder ephemeral secret key (hex).
    #[serde(default)]
    pub resp_ephemeral: Option<String>,
    /// Responder static secret key (hex).
    #[serde(default)]
    pub resp_static: Option<String>,
    /// The initiator's static public key as known to the responder (hex).
    #[serde(default)]
    pub resp_remote_static: Option<String>,
    /// Expected final handshake hash (hex).
    #[serde(default)]
    pub handshake_hash: Option<String>,
    /// The message transcript.
    pub messages: Vec<VectorMessage>,
}

/// The top-level vector file.
#[derive(Clone, Debug, Deserialize)]
pub struct VectorFile {
    /// All vectors.
    pub vectors: Vec<Vector>,
}

impl VectorFile {
    /// Parses a vector file from JSON.
    pub fn from_json(json: &str) -> Result<Self, NoiseError> {
        serde_json::from_str(json)
            .map_err(|e| NoiseError::InvalidState(Box::leak(e.to_string().into_boxed_str())))
    }
}

/// A specific failure while running a vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VectorMismatch {
    /// The protocol name could not be parsed or is unsupported.
    UnsupportedProtocol(String),
    /// A key in the vector could not be imported.
    BadKey(String),
    /// The handshake failed at a given message.
    HandshakeFailed { message: usize, error: String },
    /// A ciphertext differed from the vector.
    CiphertextMismatch {
        /// Message index.
        message: usize,
        /// Which party wrote it.
        sender: Role,
        /// Expected bytes (hex).
        expected: String,
        /// Produced bytes (hex).
        actual: String,
    },
    /// A decrypted payload differed from the vector.
    PayloadMismatch {
        /// Message index.
        message: usize,
        /// Expected payload (hex).
        expected: String,
        /// Decrypted payload (hex).
        actual: String,
    },
    /// The final handshake hashes differed.
    HandshakeHashMismatch {
        /// Expected (hex).
        expected: String,
        /// Actual (hex).
        actual: String,
    },
    /// The vector was expected to fail but succeeded, or vice versa.
    UnexpectedOutcome,
}

impl std::fmt::Display for VectorMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorMismatch::UnsupportedProtocol(p) => write!(f, "unsupported protocol {p}"),
            VectorMismatch::BadKey(k) => write!(f, "invalid key material for {k}"),
            VectorMismatch::HandshakeFailed { message, error } => {
                write!(f, "handshake failed at message {message}: {error}")
            }
            VectorMismatch::CiphertextMismatch { message, sender, expected, actual } => write!(
                f,
                "message {message} ({sender}) ciphertext mismatch\n  expected {expected}\n  actual   {actual}"
            ),
            VectorMismatch::PayloadMismatch { message, expected, actual } => write!(
                f,
                "message {message} payload mismatch\n  expected {expected}\n  actual   {actual}"
            ),
            VectorMismatch::HandshakeHashMismatch { expected, actual } => write!(
                f,
                "handshake hash mismatch\n  expected {expected}\n  actual   {actual}"
            ),
            VectorMismatch::UnexpectedOutcome => write!(f, "unexpected pass/fail outcome"),
        }
    }
}

fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>, VectorMismatch> {
    hex::decode(value).map_err(|_| VectorMismatch::BadKey(name.to_owned()))
}

fn key_pair(
    name: &str,
    dh: DhKind,
    value: &Option<String>,
) -> Result<Option<KeyPair>, VectorMismatch> {
    match value {
        None => Ok(None),
        Some(hex_value) => {
            let bytes = decode_hex(name, hex_value)?;
            KeyPair::from_secret(dh, &bytes)
                .map(Some)
                .map_err(|_| VectorMismatch::BadKey(name.to_owned()))
        }
    }
}

fn public_key(
    name: &str,
    dh: DhKind,
    value: &Option<String>,
) -> Result<Option<PublicKey>, VectorMismatch> {
    match value {
        None => Ok(None),
        Some(hex_value) => {
            let bytes = decode_hex(name, hex_value)?;
            PublicKey::from_bytes(dh, &bytes)
                .map(Some)
                .map_err(|_| VectorMismatch::BadKey(name.to_owned()))
        }
    }
}

fn psk(value: &Option<String>) -> Result<Option<[u8; 32]>, VectorMismatch> {
    match value {
        None => Ok(None),
        Some(hex_value) => {
            let bytes = decode_hex("psk", hex_value)?;
            if bytes.len() != 32 {
                return Err(VectorMismatch::BadKey("psk must be 32 bytes".to_owned()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
    }
}

/// The result of running one vector.
#[derive(Clone, Debug)]
pub struct VectorOutcome {
    /// The protocol name under test.
    pub protocol_name: String,
    /// The computed handshake hash (hex), if the handshake completed.
    pub handshake_hash: Option<String>,
    /// The number of messages processed.
    pub messages_processed: usize,
}

/// Builds the initiator/responder pair for a vector, using the fixed keys and
/// prologues the vector specifies. Useful for negative tests that need to
/// drive a real state machine.
pub fn build_pair(vector: &Vector) -> Result<(HandshakeState, HandshakeState), NoiseError> {
    let params = ProtocolParams::parse(&vector.protocol_name)?;
    let dh = params.dh;
    let cfg = |static_key: &Option<String>,
               remote: &Option<String>,
               ephemeral: &Option<String>,
               psk_hex: &Option<String>,
               prologue: &str|
     -> Result<HandshakeConfig, NoiseError> {
        Ok(HandshakeConfig {
            local_static: pair_from(static_key, dh),
            remote_static: key_from(remote, dh)?,
            local_ephemeral: pair_from(ephemeral, dh),
            remote_ephemeral: None,
            psk: psk_value(psk_hex)?,
            prologue: hex::decode(prologue)
                .map_err(|_| NoiseError::InvalidState("vector prologue is not hex"))?,
        })
    };
    let init_config = cfg(
        &vector.init_static,
        &vector.init_remote_static,
        &vector.init_ephemeral,
        &vector.init_psk,
        &vector.init_prologue,
    )?;
    let resp_config = cfg(
        &vector.resp_static,
        &vector.resp_remote_static,
        &vector.resp_ephemeral,
        &vector.resp_psk,
        &vector.resp_prologue,
    )?;
    let initiator =
        HandshakeState::new(params.clone(), Role::Initiator, init_config, TraceMode::Off)?;
    let responder = HandshakeState::new(params, Role::Responder, resp_config, TraceMode::Off)?;
    Ok((initiator, responder))
}

fn pair_from(value: &Option<String>, dh: DhKind) -> Option<KeyPair> {
    value
        .as_ref()
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| KeyPair::from_secret(dh, &bytes).ok())
}

fn key_from(value: &Option<String>, dh: DhKind) -> Result<Option<PublicKey>, NoiseError> {
    match value {
        None => Ok(None),
        Some(hex_value) => {
            let bytes = hex::decode(hex_value)
                .map_err(|_| NoiseError::InvalidState("vector key is not hex"))?;
            PublicKey::from_bytes(dh, &bytes).map(Some)
        }
    }
}

fn psk_value(value: &Option<String>) -> Result<Option<[u8; 32]>, NoiseError> {
    match value {
        None => Ok(None),
        Some(hex_value) => {
            let bytes = hex::decode(hex_value)
                .map_err(|_| NoiseError::InvalidState("vector psk is not hex"))?;
            if bytes.len() != 32 {
                return Err(NoiseError::InvalidKeyLength {
                    expected: 32,
                    got: bytes.len(),
                });
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
    }
}

/// Runs one vector end-to-end: initiator and responder alternate, every
/// produced ciphertext is compared with the vector, every decrypted payload is
/// compared, and the final handshake hash is compared.
///
/// Traces are disabled here; use [`run_vector_traced`] to collect them.
pub fn run_vector(vector: &Vector) -> Result<VectorOutcome, VectorMismatch> {
    run_vector_traced(vector, TraceMode::Off)
}

/// Like [`run_vector`], but with a trace mode the caller selects. Traces are
/// discarded; this is mainly useful from tests and the CLI.
pub fn run_vector_traced(
    vector: &Vector,
    trace_mode: TraceMode,
) -> Result<VectorOutcome, VectorMismatch> {
    let params = ProtocolParams::parse(&vector.protocol_name)
        .map_err(|_| VectorMismatch::UnsupportedProtocol(vector.protocol_name.clone()))?;
    let dh = params.dh;

    let init_config = HandshakeConfig {
        local_static: key_pair("init_static", dh, &vector.init_static)?,
        remote_static: public_key("init_remote_static", dh, &vector.init_remote_static)?,
        local_ephemeral: key_pair("init_ephemeral", dh, &vector.init_ephemeral)?,
        remote_ephemeral: None,
        psk: psk(&vector.init_psk)?,
        prologue: decode_hex("init_prologue", &vector.init_prologue)?,
    };
    let resp_config = HandshakeConfig {
        local_static: key_pair("resp_static", dh, &vector.resp_static)?,
        remote_static: public_key("resp_remote_static", dh, &vector.resp_remote_static)?,
        local_ephemeral: key_pair("resp_ephemeral", dh, &vector.resp_ephemeral)?,
        remote_ephemeral: None,
        psk: psk(&vector.resp_psk)?,
        prologue: decode_hex("resp_prologue", &vector.resp_prologue)?,
    };

    let initiator = HandshakeState::new(params.clone(), Role::Initiator, init_config, trace_mode)
        .map_err(|e| VectorMismatch::UnsupportedProtocol(e.to_string()))?;
    let responder = HandshakeState::new(params.clone(), Role::Responder, resp_config, trace_mode)
        .map_err(|e| VectorMismatch::UnsupportedProtocol(e.to_string()))?;

    // The handshake states are consumed by `into_transport`; they are held in
    // `Option`s so the transport phase can take ownership.
    let mut hs_init: Option<HandshakeState> = Some(initiator);
    let mut hs_resp: Option<HandshakeState> = Some(responder);

    // One-way patterns never alternate sender: the initiator sends the
    // handshake message and every subsequent transport message.
    let one_way = matches!(
        params.pattern.name,
        "N" | "K" | "X" | "Npsk0" | "Kpsk0" | "Xpsk1"
    );

    let mut transport: Option<(TransportState, TransportState)> = None;
    let mut hashes: Option<(Vec<u8>, Vec<u8>)> = None;
    let mut processed = 0usize;
    // cacophony's vector file records, as `handshake_hash`, the value its
    // reference implementation happens to hold at its last suspension point:
    // `h` at the start of the final handshake message, or immediately before
    // the final `psk` token if that message contains one. The handshake state
    // tracks exactly that checkpoint, so the comparison is byte-exact.
    let mut reported_hash: Option<Vec<u8>> = None;
    let mut checkpoint: Option<Vec<u8>> = None;

    for (index, expected) in vector.messages.iter().enumerate() {
        let expected_payload = decode_hex("payload", &expected.payload)?;
        let expected_ciphertext = decode_hex("ciphertext", &expected.ciphertext)?;

        let handshake_done = hs_init.as_ref().map(|h| h.is_complete()).unwrap_or(true);

        if !handshake_done {
            let sender = hs_init
                .as_ref()
                .and_then(|h| h.next_sender())
                .ok_or_else(|| VectorMismatch::HandshakeFailed {
                    message: index,
                    error: "pattern has no further messages".to_owned(),
                })?;

            let produced = match sender {
                Role::Initiator => hs_init.as_mut().unwrap().write_message(&expected_payload),
                Role::Responder => hs_resp.as_mut().unwrap().write_message(&expected_payload),
            }
            .map_err(|e| VectorMismatch::HandshakeFailed {
                message: index,
                error: e.to_string(),
            })?;

            if produced.bytes != expected_ciphertext {
                return Err(VectorMismatch::CiphertextMismatch {
                    message: index,
                    sender,
                    expected: hex::encode(&expected_ciphertext),
                    actual: hex::encode(&produced.bytes),
                });
            }

            let received = match sender {
                Role::Initiator => hs_resp.as_mut().unwrap().read_message(&expected_ciphertext),
                Role::Responder => hs_init.as_mut().unwrap().read_message(&expected_ciphertext),
            }
            .map_err(|e| VectorMismatch::HandshakeFailed {
                message: index,
                error: e.to_string(),
            })?;

            if received.payload != expected_payload {
                return Err(VectorMismatch::PayloadMismatch {
                    message: index,
                    expected: hex::encode(&expected_payload),
                    actual: hex::encode(&received.payload),
                });
            }

            if hs_init.as_ref().map(|h| h.is_complete()).unwrap_or(false) {
                let init_state = hs_init.as_ref().unwrap();
                let resp_state = hs_resp.as_ref().unwrap();
                hashes = Some((init_state.handshake_hash(), resp_state.handshake_hash()));
                reported_hash = Some(init_state.checkpoint_hash().to_vec());
                checkpoint = Some(resp_state.checkpoint_hash().to_vec());
            }
        } else {
            // Transport phase. Interactive patterns alternate the sender
            // (handshake message indices included); one-way patterns keep the
            // initiator as the only sender.
            if transport.is_none() {
                let init_transport = hs_init
                    .take()
                    .ok_or_else(|| VectorMismatch::HandshakeFailed {
                        message: index,
                        error: "initiator handshake state already consumed".to_owned(),
                    })?
                    .into_transport()
                    .map_err(|e| VectorMismatch::HandshakeFailed {
                        message: index,
                        error: e.to_string(),
                    })?;
                let resp_transport = hs_resp
                    .take()
                    .ok_or_else(|| VectorMismatch::HandshakeFailed {
                        message: index,
                        error: "responder handshake state already consumed".to_owned(),
                    })?
                    .into_transport()
                    .map_err(|e| VectorMismatch::HandshakeFailed {
                        message: index,
                        error: e.to_string(),
                    })?;
                transport = Some((init_transport, resp_transport));
            }

            let (init_transport, resp_transport) =
                transport.as_mut().expect("transport states created above");
            let from_initiator = one_way || index % 2 == 0;
            let (sender_tx, receiver_tx) = if from_initiator {
                (init_transport, resp_transport)
            } else {
                (resp_transport, init_transport)
            };

            let produced =
                sender_tx
                    .send(&expected_payload)
                    .map_err(|e| VectorMismatch::HandshakeFailed {
                        message: index,
                        error: e.to_string(),
                    })?;
            if produced != expected_ciphertext {
                return Err(VectorMismatch::CiphertextMismatch {
                    message: index,
                    sender: if from_initiator {
                        Role::Initiator
                    } else {
                        Role::Responder
                    },
                    expected: hex::encode(&expected_ciphertext),
                    actual: hex::encode(&produced),
                });
            }
            let received = receiver_tx.receive(&expected_ciphertext).map_err(|e| {
                VectorMismatch::HandshakeFailed {
                    message: index,
                    error: e.to_string(),
                }
            })?;
            if received != expected_payload {
                return Err(VectorMismatch::PayloadMismatch {
                    message: index,
                    expected: hex::encode(&expected_payload),
                    actual: hex::encode(&received),
                });
            }
        }

        processed += 1;
    }

    // The handshake hash is captured before the states are consumed by
    // `into_transport` (or read directly when the transcript is one-way and
    // short enough to leave the handshake state alive).
    let (init_hash, resp_hash) = hashes.ok_or_else(|| VectorMismatch::HandshakeFailed {
        message: processed,
        error: "transcript ended before the handshake completed".to_owned(),
    })?;
    if init_hash != resp_hash {
        return Err(VectorMismatch::HandshakeHashMismatch {
            expected: hex::encode(&init_hash),
            actual: hex::encode(&resp_hash),
        });
    }
    if let Some(expected) = &vector.handshake_hash {
        let expected_bytes = decode_hex("handshake_hash", expected)?;
        let actual = reported_hash.unwrap_or_else(|| init_hash.clone());
        // Both parties must agree on the reference checkpoint too.
        if let Some(other) = &checkpoint {
            if *other != actual {
                return Err(VectorMismatch::HandshakeHashMismatch {
                    expected: hex::encode(&actual),
                    actual: hex::encode(other),
                });
            }
        }
        if actual != expected_bytes {
            return Err(VectorMismatch::HandshakeHashMismatch {
                expected: hex::encode(&expected_bytes),
                actual: hex::encode(&actual),
            });
        }
    }
    if vector.fail {
        return Err(VectorMismatch::UnexpectedOutcome);
    }

    Ok(VectorOutcome {
        protocol_name: vector.protocol_name.clone(),
        handshake_hash: Some(hex::encode(&init_hash)),
        messages_processed: processed,
    })
}
