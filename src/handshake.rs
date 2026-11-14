//! The `HandshakeState`: the strict Noise handshake state machine.
//!
//! This module implements sections 5.3, 6, 7.4 and 9.2 of the Noise
//! specification. The state machine is deliberately non-permissive:
//!
//! * every call declares which party is sending or receiving, and a role
//!   mismatch is an error rather than an implicit role flip;
//! * messages must be consumed in the exact order of the pattern; there is no
//!   way to skip, re-read or re-order one (a replayed or out-of-order message
//!   is therefore rejected instead of being interpreted as a different step);
//! * a message must be at least as long as its tokens require, and trailing
//!   bytes after the payload are rejected;
//! * a token that needs a key which is not configured fails immediately;
//! * an `s` token will not silently overwrite a remote static key that is
//!   already known;
//! * the PSK validity rule (section 9.3) is enforced;
//! * handshake messages are capped at 65535 bytes (section 3).

use crate::crypto::{KeyPair, PublicKey, TAG_LEN};
use crate::error::NoiseError;
use crate::params::ProtocolParams;
use crate::patterns::{Role, Token};
use crate::symmetric::{CipherState, SymmetricState};
use crate::trace::{TraceEvent, TraceLog, TraceMode};

/// Maximum size of any Noise message, per section 3 of the specification.
pub const MAX_MESSAGE_LEN: usize = 65535;

/// A handshake message produced by [`HandshakeState::write_message`].
#[derive(Clone, Debug)]
pub struct HandshakeMessage {
    /// Zero-based index of this message in the pattern.
    pub index: usize,
    /// The sending party.
    pub sender: Role,
    /// The wire bytes to transmit.
    pub bytes: Vec<u8>,
    /// The plaintext payload that was carried.
    pub payload: Vec<u8>,
}

/// A handshake message consumed by [`HandshakeState::read_message`].
#[derive(Clone, Debug)]
pub struct ReceivedMessage {
    /// Zero-based index of this message in the pattern.
    pub index: usize,
    /// The sending party.
    pub sender: Role,
    /// The authenticated plaintext payload.
    pub payload: Vec<u8>,
}

/// Static configuration for [`HandshakeState::new`].
#[derive(Clone, Default, Debug)]
pub struct HandshakeConfig {
    /// This party's static key pair, when the pattern calls for one.
    pub local_static: Option<KeyPair>,
    /// The peer's static public key, when it is known out of band (pre-message
    /// `s` on the peer's side, or `es`/`se`/`ss` before the key is received).
    pub remote_static: Option<PublicKey>,
    /// A pre-generated ephemeral key pair. Test vectors supply one; in
    /// production leave this `None` so a fresh key is generated per handshake.
    pub local_ephemeral: Option<KeyPair>,
    /// The peer's ephemeral public key, only for patterns with a pre-message
    /// `e` (none of the supported patterns use one, but the API allows it).
    pub remote_ephemeral: Option<PublicKey>,
    /// The pre-shared key, required exactly when the pattern contains `psk`.
    pub psk: Option<[u8; 32]>,
    /// Prologue data mixed into the initial hash (section 6).
    pub prologue: Vec<u8>,
}

/// The handshake state machine.
#[derive(Debug)]
pub struct HandshakeState {
    /// Negotiated parameters.
    pub(crate) params: ProtocolParams,
    role: Role,
    symmetric: SymmetricState,
    local_static: Option<KeyPair>,
    local_ephemeral: Option<KeyPair>,
    remote_static: Option<PublicKey>,
    remote_ephemeral: Option<PublicKey>,
    psk: Option<[u8; 32]>,
    /// Index of the next message to produce or consume.
    next_message: usize,
    /// Whether an `e` token has been sent (PSK validity rule).
    sent_ephemeral: bool,
    /// Whether a `psk` token has been processed.
    psk_mixed: bool,
    /// Set once the last message in the pattern has been processed.
    complete: bool,
    /// Set when any message was rejected. A rejected message may already have
    /// mixed tokens into the symmetric state before the failure was detected,
    /// so continuing from it would run the pattern against corrupted `h`/`ck`.
    /// Once poisoned, every further operation fails.
    poisoned: bool,
    /// Split cipher states, available once `complete`.
    split: Option<(CipherState, CipherState)>,
    /// `h` at completion, kept as the handshake hash.
    final_hash: Vec<u8>,
    /// The `h` value at the most recent reference-implementation checkpoint.
    ///
    /// The cacophony reference implementation reports its handshake state as
    /// of the last point where its interpreter suspended (the start of a
    /// message, or a `psk` request). That value is useful for byte-exact
    /// comparison against its vector file, but it is not the section 11.2
    /// handshake hash. Kept purely for vector checking.
    checkpoint_h: Vec<u8>,
    trace: TraceLog,
}

impl Drop for HandshakeState {
    fn drop(&mut self) {
        if let Some(psk) = self.psk.as_mut() {
            zeroize::Zeroize::zeroize(psk);
        }
    }
}

impl HandshakeState {
    /// Creates a handshake state.
    ///
    /// `trace` selects how much detail is recorded; drain it with
    /// [`HandshakeState::take_trace`].
    pub fn new(
        params: ProtocolParams,
        role: Role,
        config: HandshakeConfig,
        trace_mode: TraceMode,
    ) -> Result<Self, NoiseError> {
        validate_config(&params, role, &config)?;

        let protocol_name = params.protocol_name();
        let mut symmetric = SymmetricState::new(params.cipher, params.hash, &protocol_name);
        symmetric.mix_hash(&config.prologue);

        let mut state = HandshakeState {
            params,
            role,
            symmetric,
            local_static: config.local_static,
            local_ephemeral: config.local_ephemeral,
            remote_static: config.remote_static,
            remote_ephemeral: config.remote_ephemeral,
            psk: config.psk,
            next_message: 0,
            sent_ephemeral: false,
            psk_mixed: false,
            complete: false,
            poisoned: false,
            split: None,
            final_hash: Vec::new(),
            checkpoint_h: Vec::new(),
            trace: TraceLog::new(trace_mode),
        };

        state.trace.push(TraceEvent::Init {
            protocol_name: String::from_utf8_lossy(&protocol_name).into_owned(),
            role,
            psk_mode: state.params.pattern.psk_mode,
            prologue: hex::encode(&config.prologue),
            h: hex::encode(state.symmetric.h()),
            ck: state.trace.secret(state.symmetric.ck()),
        });

        state.process_pre_messages()?;
        state.checkpoint_h = state.symmetric.h().to_vec();
        Ok(state)
    }

    /// This party's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The negotiated parameters.
    pub fn params(&self) -> &ProtocolParams {
        &self.params
    }

    /// Zero-based index of the next message.
    pub fn next_message_index(&self) -> usize {
        self.next_message
    }

    /// Which party must send the next message.
    pub fn next_sender(&self) -> Option<Role> {
        self.params.pattern.sender_of(self.next_message)
    }

    /// True once the last handshake message has been processed.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// The handshake hash (channel binding value, section 11.2).
    ///
    /// Only meaningful once [`HandshakeState::is_complete`] is true.
    pub fn handshake_hash(&self) -> Vec<u8> {
        if self.complete {
            self.final_hash.clone()
        } else {
            self.symmetric.h().to_vec()
        }
    }

    /// The reference-implementation checkpoint hash.
    ///
    /// Diagnostic only: see the `checkpoint_h` field. The spec-visible
    /// handshake hash is [`HandshakeState::handshake_hash`].
    pub(crate) fn checkpoint_hash(&self) -> &[u8] {
        &self.checkpoint_h
    }

    /// Marks the start of a handshake message, recording the checkpoint `h`
    /// used for byte-exact comparison against the reference vector file.
    fn begin_message(&mut self) {
        self.checkpoint_h = self.symmetric.h().to_vec();
    }

    /// The peer's static public key, once known.
    pub fn remote_static(&self) -> Option<&PublicKey> {
        self.remote_static.as_ref()
    }

    /// This party's static public key, if configured.
    pub fn local_static(&self) -> Option<&PublicKey> {
        self.local_static.as_ref().map(|k| k.public())
    }

    /// Drains recorded trace events.
    pub fn take_trace(&mut self) -> Vec<TraceEvent> {
        self.trace.take()
    }

    /// The trace mode.
    pub fn trace_mode(&self) -> TraceMode {
        self.trace.mode()
    }

    /// Writes the next handshake message with the given payload.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<HandshakeMessage, NoiseError> {
        self.check_usable("write_message")?;
        if self.complete {
            return Err(NoiseError::HandshakeComplete);
        }
        let index = self.next_message;
        let msg = self.params.pattern.messages[index].clone();
        if msg.sender != self.role {
            self.reject(
                "write_message",
                NoiseError::WrongRole {
                    expected: msg.sender.as_str(),
                },
            );
            return Err(NoiseError::WrongRole {
                expected: msg.sender.as_str(),
            });
        }
        if payload.len() > MAX_MESSAGE_LEN {
            let err = NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: payload.len(),
            };
            self.reject("write_message", err.clone());
            return Err(err);
        }

        self.begin_message();
        let mut buffer: Vec<u8> = Vec::new();
        let tokens = msg.tokens.clone();
        for token in &tokens {
            if let Err(err) = self.process_token_send(*token, index, &mut buffer) {
                // The tokens processed so far have already advanced `h`/`ck`;
                // the handshake cannot continue from here.
                self.reject("write_message", err.clone());
                return Err(err);
            }
        }
        if let Err(err) = self.check_psk_validity() {
            self.reject("write_message", err.clone());
            return Err(err);
        }

        let nonce = self
            .symmetric
            .cipher_state()
            .has_key()
            .then(|| self.symmetric.cipher_state().nonce());
        let key = self.trace.secret(
            self.symmetric
                .cipher_state()
                .key()
                .map(|k| &k[..])
                .unwrap_or(&[]),
        );
        let ad = hex::encode(self.symmetric.h());
        let ct = match self.symmetric.encrypt_and_hash(payload) {
            Ok(ct) => ct,
            Err(err) => {
                self.reject("write_message", err.clone());
                return Err(err);
            }
        };
        self.trace.push(TraceEvent::Payload {
            index,
            direction: "encrypt",
            nonce,
            ad,
            key,
            input_len: payload.len(),
            output_len: ct.len(),
            bytes: hex::encode(&ct),
            ok: true,
            h_after: hex::encode(self.symmetric.h()),
        });
        buffer.extend_from_slice(&ct);

        if buffer.len() > MAX_MESSAGE_LEN {
            let err = NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: buffer.len(),
            };
            self.reject("write_message", err.clone());
            return Err(err);
        }

        self.trace.push(TraceEvent::Message {
            index,
            sender: self.role,
            direction: "write",
            payload_len: payload.len(),
            wire_len: buffer.len(),
            wire: hex::encode(&buffer),
        });

        self.advance()?;

        Ok(HandshakeMessage {
            index,
            sender: self.role,
            bytes: buffer,
            payload: payload.to_vec(),
        })
    }

    /// Reads the next handshake message.
    ///
    /// Out-of-order or replayed messages fail here: the pattern fixes which
    /// message may come next and the AEAD associated data chains every prior
    /// message, so anything else is rejected.
    pub fn read_message(&mut self, message: &[u8]) -> Result<ReceivedMessage, NoiseError> {
        self.check_usable("read_message")?;
        if self.complete {
            return Err(NoiseError::HandshakeComplete);
        }
        let index = self.next_message;
        let msg = self.params.pattern.messages[index].clone();
        if msg.sender == self.role {
            let err = NoiseError::WrongRole {
                expected: msg.sender.peer().as_str(),
            };
            self.reject("read_message", err.clone());
            return Err(err);
        }
        if message.len() > MAX_MESSAGE_LEN {
            let err = NoiseError::MessageTooLong {
                max: MAX_MESSAGE_LEN,
                got: message.len(),
            };
            self.reject("read_message", err.clone());
            return Err(err);
        }

        self.begin_message();
        let mut cursor = 0usize;
        let tokens = msg.tokens.clone();
        for token in &tokens {
            match self.process_token_recv(*token, index, message, &mut cursor) {
                Ok(()) => {}
                Err(err) => {
                    self.reject("read_message", err.clone());
                    return Err(err);
                }
            }
        }

        let remaining = &message[cursor..];
        let nonce = self
            .symmetric
            .cipher_state()
            .has_key()
            .then(|| self.symmetric.cipher_state().nonce());
        let key = self.trace.secret(
            self.symmetric
                .cipher_state()
                .key()
                .map(|k| &k[..])
                .unwrap_or(&[]),
        );
        let ad = hex::encode(self.symmetric.h());
        let plaintext = match self.symmetric.decrypt_and_hash(remaining) {
            Ok(pt) => pt,
            Err(err) => {
                self.trace.push(TraceEvent::Payload {
                    index,
                    direction: "decrypt",
                    nonce,
                    ad,
                    key,
                    input_len: remaining.len(),
                    output_len: 0,
                    bytes: hex::encode(remaining),
                    ok: false,
                    h_after: hex::encode(self.symmetric.h()),
                });
                self.reject("read_message", err.clone());
                return Err(err);
            }
        };

        self.trace.push(TraceEvent::Payload {
            index,
            direction: "decrypt",
            nonce,
            ad,
            key,
            input_len: remaining.len(),
            output_len: plaintext.len(),
            bytes: hex::encode(remaining),
            ok: true,
            h_after: hex::encode(self.symmetric.h()),
        });
        self.trace.push(TraceEvent::Message {
            index,
            sender: msg.sender,
            direction: "read",
            payload_len: plaintext.len(),
            wire_len: message.len(),
            wire: hex::encode(message),
        });

        self.advance()?;

        Ok(ReceivedMessage {
            index,
            sender: msg.sender,
            payload: plaintext,
        })
    }

    /// Converts a completed handshake into transport states.
    pub fn into_transport(mut self) -> Result<TransportState, NoiseError> {
        let (c1, c2) = self.split.take().ok_or(NoiseError::HandshakeIncomplete)?;
        let handshake_hash = self.final_hash.clone();
        let (sending, receiving) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };
        let trace = std::mem::take(&mut self.trace);
        Ok(TransportState::new(
            self.role,
            self.params.cipher,
            sending,
            receiving,
            handshake_hash,
            trace,
        ))
    }

    // -- internals ---------------------------------------------------------

    fn reject(&mut self, operation: &'static str, err: NoiseError) {
        self.poisoned = true;
        self.trace.push(TraceEvent::Rejected {
            operation,
            reason: err.to_string(),
        });
    }

    fn check_usable(&mut self, operation: &'static str) -> Result<(), NoiseError> {
        if self.poisoned {
            let err = NoiseError::InvalidState(
                "handshake aborted by an earlier rejected message; start a new one",
            );
            self.trace.push(TraceEvent::Rejected {
                operation,
                reason: err.to_string(),
            });
            return Err(err);
        }
        Ok(())
    }

    /// Increments the message counter and completes the handshake at the end.
    fn advance(&mut self) -> Result<(), NoiseError> {
        self.next_message += 1;
        if self.next_message == self.params.pattern.messages.len() {
            self.complete = true;
            let (c1, c2) = self.symmetric.split();
            self.final_hash = self.symmetric.h().to_vec();
            let (send_key, recv_key) = match self.role {
                Role::Initiator => (
                    c1.key().copied().unwrap_or([0u8; 32]),
                    c2.key().copied().unwrap_or([0u8; 32]),
                ),
                Role::Responder => (
                    c2.key().copied().unwrap_or([0u8; 32]),
                    c1.key().copied().unwrap_or([0u8; 32]),
                ),
            };
            let k1_bytes = c1.key().copied().unwrap_or([0u8; 32]);
            let k2_bytes = c2.key().copied().unwrap_or([0u8; 32]);
            self.split = Some((c1, c2));
            self.trace.push(TraceEvent::Split {
                handshake_hash: hex::encode(&self.final_hash),
                k1: self.trace.secret(&k1_bytes),
                k2: self.trace.secret(&k2_bytes),
                sending_key: self.trace.secret(&send_key),
                receiving_key: self.trace.secret(&recv_key),
            });
        }
        Ok(())
    }

    /// Mixes the pre-message public keys into `h`.
    fn process_pre_messages(&mut self) -> Result<(), NoiseError> {
        let pre_init = self.params.pattern.pre_initiator.clone();
        let pre_resp = self.params.pattern.pre_responder.clone();
        for token in pre_init {
            self.process_pre_token(Role::Initiator, token)?;
        }
        for token in pre_resp {
            self.process_pre_token(Role::Responder, token)?;
        }
        Ok(())
    }

    fn process_pre_token(&mut self, sender: Role, token: Token) -> Result<(), NoiseError> {
        let public = match token {
            Token::E => {
                if sender == self.role {
                    self.local_ephemeral
                        .as_ref()
                        .ok_or(NoiseError::MissingKey("local ephemeral (pre-message e)"))?
                        .public()
                        .clone()
                } else {
                    self.remote_ephemeral
                        .clone()
                        .ok_or(NoiseError::MissingKey("remote ephemeral (pre-message e)"))?
                }
            }
            Token::S => {
                if sender == self.role {
                    self.local_static
                        .as_ref()
                        .ok_or(NoiseError::MissingKey("local static (pre-message s)"))?
                        .public()
                        .clone()
                } else {
                    self.remote_static
                        .clone()
                        .ok_or(NoiseError::MissingKey("remote static (pre-message s)"))?
                }
            }
            _ => {
                return Err(NoiseError::InvalidState(
                    "only e and s are valid pre-message tokens",
                ))
            }
        };
        self.symmetric.mix_hash(public.as_bytes());
        self.trace.push(TraceEvent::PreMessage {
            sender,
            token,
            public_key: hex::encode(public.as_bytes()),
            h: hex::encode(self.symmetric.h()),
        });
        Ok(())
    }

    /// The PSK validity rule from section 9.3: a party may not send encrypted
    /// data after mixing a `psk` unless it has already sent an ephemeral key.
    fn check_psk_validity(&self) -> Result<(), NoiseError> {
        if self.psk_mixed && !self.sent_ephemeral && self.symmetric.cipher_state().has_key() {
            return Err(NoiseError::InvalidState(
                "PSK validity rule: cannot encrypt before sending an ephemeral key",
            ));
        }
        Ok(())
    }

    fn local_ephemeral(&mut self) -> Result<KeyPair, NoiseError> {
        if let Some(kp) = &self.local_ephemeral {
            return Ok(kp.clone());
        }
        let kp = KeyPair::generate(self.params.dh)?;
        self.local_ephemeral = Some(kp.clone());
        Ok(kp)
    }

    fn require_local_static(&self) -> Result<KeyPair, NoiseError> {
        self.local_static
            .clone()
            .ok_or(NoiseError::MissingKey("local static"))
    }

    fn require_remote_static(&self) -> Result<PublicKey, NoiseError> {
        self.remote_static
            .clone()
            .ok_or(NoiseError::MissingKey("remote static"))
    }

    fn require_remote_ephemeral(&self) -> Result<PublicKey, NoiseError> {
        self.remote_ephemeral
            .clone()
            .ok_or(NoiseError::MissingKey("remote ephemeral"))
    }

    /// Reads exactly `len` bytes at `cursor`, advancing it.
    fn take<'a>(
        &self,
        message: &'a [u8],
        cursor: &mut usize,
        len: usize,
        what: &'static str,
    ) -> Result<&'a [u8], NoiseError> {
        let end = cursor.checked_add(len).ok_or(NoiseError::MessageTooShort {
            needed: len,
            got: message.len(),
        })?;
        if end > message.len() {
            return Err(NoiseError::MessageTooShort {
                needed: end,
                got: message.len(),
            });
        }
        let out = &message[*cursor..end];
        *cursor = end;
        let _ = what;
        Ok(out)
    }

    // -- token handling: sending side --------------------------------------

    fn process_token_send(
        &mut self,
        token: Token,
        index: usize,
        buffer: &mut Vec<u8>,
    ) -> Result<(), NoiseError> {
        match token {
            Token::E => {
                let eph = self.local_ephemeral()?;
                let public = eph.public().clone();
                buffer.extend_from_slice(public.as_bytes());
                self.symmetric.mix_hash(public.as_bytes());
                if self.params.pattern.psk_mode {
                    self.symmetric.mix_key(public.as_bytes());
                }
                self.sent_ephemeral = true;
                self.trace_token(
                    index,
                    token,
                    vec![("public_key", hex::encode(public.as_bytes()))],
                );
            }
            Token::S => {
                let static_key = self.require_local_static()?;
                let public = static_key.public().clone();
                // `S` encrypts, so the PSK validity rule applies here too.
                self.check_psk_validity()?;
                let ct = self.symmetric.encrypt_and_hash(public.as_bytes())?;
                buffer.extend_from_slice(&ct);
                self.trace_token(
                    index,
                    token,
                    vec![
                        ("public_key", hex::encode(public.as_bytes())),
                        ("ciphertext", hex::encode(&ct)),
                    ],
                );
            }
            Token::Ee => {
                let eph = self
                    .local_ephemeral
                    .clone()
                    .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                let remote = self.require_remote_ephemeral()?;
                let shared = eph.diffie_hellman(&remote)?;
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Es => {
                let shared = match self.role {
                    Role::Initiator => {
                        let eph = self
                            .local_ephemeral
                            .clone()
                            .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                        eph.diffie_hellman(&self.require_remote_static()?)?
                    }
                    Role::Responder => {
                        let s = self.require_local_static()?;
                        s.diffie_hellman(&self.require_remote_ephemeral()?)?
                    }
                };
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Se => {
                let shared = match self.role {
                    Role::Initiator => {
                        let s = self.require_local_static()?;
                        s.diffie_hellman(&self.require_remote_ephemeral()?)?
                    }
                    Role::Responder => {
                        let eph = self
                            .local_ephemeral
                            .clone()
                            .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                        eph.diffie_hellman(&self.require_remote_static()?)?
                    }
                };
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Ss => {
                let local = self.require_local_static()?;
                let remote = self.require_remote_static()?;
                let shared = local.diffie_hellman(&remote)?;
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Psk => {
                let psk = self.psk.ok_or(NoiseError::PskRequired)?;
                self.checkpoint_h = self.symmetric.h().to_vec();
                self.symmetric.mix_key_and_hash(&psk);
                self.psk_mixed = true;
                self.trace_token(index, token, vec![("psk_len", psk.len().to_string())]);
            }
        }
        Ok(())
    }

    // -- token handling: receiving side ------------------------------------

    fn process_token_recv(
        &mut self,
        token: Token,
        index: usize,
        message: &[u8],
        cursor: &mut usize,
    ) -> Result<(), NoiseError> {
        match token {
            Token::E => {
                let len = self.params.dh.key_len();
                let bytes = self.take(message, cursor, len, "ephemeral key")?;
                let public = PublicKey::from_bytes(self.params.dh, bytes)?;
                self.symmetric.mix_hash(public.as_bytes());
                if self.params.pattern.psk_mode {
                    self.symmetric.mix_key(public.as_bytes());
                }
                self.remote_ephemeral = Some(public.clone());
                self.trace_token(
                    index,
                    token,
                    vec![("public_key", hex::encode(public.as_bytes()))],
                );
            }
            Token::S => {
                let key_len = self.params.dh.key_len();
                let has_key = self.symmetric.cipher_state().has_key();
                let total = key_len + if has_key { TAG_LEN } else { 0 };
                let bytes = self.take(message, cursor, total, "static key")?;
                let plaintext = self.symmetric.decrypt_and_hash(bytes)?;
                if plaintext.len() != key_len {
                    return Err(NoiseError::InvalidPublicKey("static key has wrong length"));
                }
                let public = PublicKey::from_bytes(self.params.dh, &plaintext)?;
                if self.remote_static.is_some() {
                    return Err(NoiseError::UnexpectedStaticKey);
                }
                self.remote_static = Some(public.clone());
                self.trace_token(
                    index,
                    token,
                    vec![
                        ("public_key", hex::encode(public.as_bytes())),
                        ("ciphertext", hex::encode(bytes)),
                        ("encrypted", has_key.to_string()),
                    ],
                );
            }
            Token::Ee => {
                let eph = self
                    .local_ephemeral
                    .clone()
                    .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                let remote = self.require_remote_ephemeral()?;
                let shared = eph.diffie_hellman(&remote)?;
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Es => {
                let shared = match self.role {
                    Role::Initiator => {
                        let eph = self
                            .local_ephemeral
                            .clone()
                            .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                        eph.diffie_hellman(&self.require_remote_static()?)?
                    }
                    Role::Responder => {
                        let s = self.require_local_static()?;
                        s.diffie_hellman(&self.require_remote_ephemeral()?)?
                    }
                };
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Se => {
                let shared = match self.role {
                    Role::Initiator => {
                        let s = self.require_local_static()?;
                        s.diffie_hellman(&self.require_remote_ephemeral()?)?
                    }
                    Role::Responder => {
                        let eph = self
                            .local_ephemeral
                            .clone()
                            .ok_or(NoiseError::MissingKey("local ephemeral"))?;
                        eph.diffie_hellman(&self.require_remote_static()?)?
                    }
                };
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Ss => {
                let local = self.require_local_static()?;
                let remote = self.require_remote_static()?;
                let shared = local.diffie_hellman(&remote)?;
                self.symmetric.mix_key(&shared);
                self.trace_token(index, token, vec![("dh", hex::encode(&shared))]);
            }
            Token::Psk => {
                let psk = self.psk.ok_or(NoiseError::PskRequired)?;
                self.checkpoint_h = self.symmetric.h().to_vec();
                self.symmetric.mix_key_and_hash(&psk);
                self.psk_mixed = true;
                self.trace_token(index, token, vec![("psk_len", psk.len().to_string())]);
            }
        }
        Ok(())
    }

    fn trace_token(&mut self, index: usize, token: Token, details: Vec<(&'static str, String)>) {
        let ck = self.symmetric.ck().to_vec();
        let event = TraceEvent::Token {
            index,
            token,
            details,
            h: hex::encode(self.symmetric.h()),
            ck: self.trace.secret(&ck),
            has_key: self.symmetric.cipher_state().has_key(),
            nonce: self.symmetric.cipher_state().nonce(),
        };
        self.trace.push(event);
    }
}

/// Validates the caller's configuration against the pattern for their role.
fn validate_config(
    params: &ProtocolParams,
    role: Role,
    config: &HandshakeConfig,
) -> Result<(), NoiseError> {
    // Key kinds must match the negotiated DH function.
    if let Some(kp) = &config.local_static {
        if kp.public().kind() != params.dh {
            return Err(NoiseError::InvalidState(
                "local static key uses a different DH function",
            ));
        }
    }
    if let Some(kp) = &config.local_ephemeral {
        if kp.public().kind() != params.dh {
            return Err(NoiseError::InvalidState(
                "local ephemeral key uses a different DH function",
            ));
        }
    }
    if let Some(pk) = &config.remote_static {
        if pk.kind() != params.dh {
            return Err(NoiseError::InvalidState(
                "remote static key uses a different DH function",
            ));
        }
    }
    if let Some(pk) = &config.remote_ephemeral {
        if pk.kind() != params.dh {
            return Err(NoiseError::InvalidState(
                "remote ephemeral key uses a different DH function",
            ));
        }
    }

    // PSK consistency.
    if params.pattern.psk_mode && config.psk.is_none() {
        return Err(NoiseError::PskRequired);
    }
    if !params.pattern.psk_mode && config.psk.is_some() {
        return Err(NoiseError::PskNotAllowed);
    }

    let needs = required_keys(params, role);
    if needs.local_static && config.local_static.is_none() {
        return Err(NoiseError::MissingKey("local static"));
    }
    if needs.remote_static && config.remote_static.is_none() {
        return Err(NoiseError::MissingKey("remote static"));
    }
    Ok(())
}

/// Which static keys a role needs before the handshake starts.
#[derive(Clone, Copy, Debug, Default)]
struct RequiredKeys {
    local_static: bool,
    remote_static: bool,
}

/// Which static keys a role needs to have *before the handshake starts*.
///
/// Only pre-message `s` tokens impose a startup requirement: every other
/// static key is either transmitted as an `s` token before it is used (and is
/// therefore learned during the handshake) or is a hard runtime error with a
/// precise message from the token handler.
fn required_keys(params: &ProtocolParams, role: Role) -> RequiredKeys {
    let mut req = RequiredKeys::default();
    let pattern = &params.pattern;

    for token in &pattern.pre_initiator {
        match token {
            Token::S if role == Role::Initiator => req.local_static = true,
            Token::S => req.remote_static = true,
            _ => {}
        }
    }
    for token in &pattern.pre_responder {
        match token {
            Token::S if role == Role::Responder => req.local_static = true,
            Token::S => req.remote_static = true,
            _ => {}
        }
    }
    req
}

use crate::transport::TransportState;
