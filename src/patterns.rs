//! Handshake pattern definitions from the Noise specification (sections 7 and
//! 9.4), plus a small registry used by the protocol-name parser.
//!
//! A pattern is a sequence of pre-messages and messages; each message is a
//! sequence of tokens. The roles alternate: message 0 is initiator-to-
//! responder, message 1 responder-to-initiator, and so on.

use std::fmt;

/// A handshake token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    /// Ephemeral public key.
    E,
    /// Static public key (encrypted once a key exists).
    S,
    /// `DH(e, re)`
    Ee,
    /// `DH(e, rs)` / `DH(s, re)` depending on role.
    Es,
    /// `DH(s, re)` / `DH(e, rs)` depending on role.
    Se,
    /// `DH(s, rs)`
    Ss,
    /// Pre-shared symmetric key (`MixKeyAndHash`).
    Psk,
}

impl Token {
    /// Returns the Noise token spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Token::E => "e",
            Token::S => "s",
            Token::Ee => "ee",
            Token::Es => "es",
            Token::Se => "se",
            Token::Ss => "ss",
            Token::Psk => "psk",
        }
    }
}

/// Which side of the conversation a party is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The party that sends message 0.
    Initiator,
    /// The party that receives message 0.
    Responder,
}

impl Role {
    /// The opposite role.
    pub fn peer(self) -> Role {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }

    /// Lower-case name used in diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One handshake message: who sends it and which tokens it carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagePattern {
    /// The sending role.
    pub sender: Role,
    /// Tokens, in order.
    pub tokens: Vec<Token>,
}

/// A complete handshake pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// Pattern name as it appears in a protocol name, e.g. `XXpsk3`.
    pub name: &'static str,
    /// Whether any message contains a `psk` token.
    pub psk_mode: bool,
    /// Pre-message tokens contributed by the initiator.
    pub pre_initiator: Vec<Token>,
    /// Pre-message tokens contributed by the responder.
    pub pre_responder: Vec<Token>,
    /// Message patterns in order.
    pub messages: Vec<MessagePattern>,
}

impl Pattern {
    /// Returns the role that must send message `index`.
    pub fn sender_of(&self, index: usize) -> Option<Role> {
        self.messages.get(index).map(|m| m.sender)
    }

    /// Number of handshake messages.
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

/// Builds a pattern from a compact description.
fn pattern(
    name: &'static str,
    pre_initiator: &[Token],
    pre_responder: &[Token],
    messages: &[(Role, &[Token])],
) -> Pattern {
    let psk_mode = pre_initiator
        .iter()
        .chain(pre_responder.iter())
        .chain(messages.iter().flat_map(|(_, t)| t.iter()))
        .any(|t| *t == Token::Psk);
    Pattern {
        name,
        psk_mode,
        pre_initiator: pre_initiator.to_vec(),
        pre_responder: pre_responder.to_vec(),
        messages: messages
            .iter()
            .map(|(sender, tokens)| MessagePattern {
                sender: *sender,
                tokens: tokens.to_vec(),
            })
            .collect(),
    }
}

use Role::{Initiator as I, Responder as R};
use Token::*;

/// Returns the pattern with the given name, or `None` if unknown.
///
/// The set covers every pattern in the official cacophony vector file:
/// the 15 fundamental patterns, the one-way patterns, and all PSK variants.
pub fn lookup(name: &str) -> Option<Pattern> {
    let p = match name {
        // ---- fundamental interactive patterns -------------------------
        "NN" => pattern("NN", &[], &[], &[(I, &[E]), (R, &[E, Ee])]),
        "KN" => pattern("KN", &[S], &[], &[(I, &[E]), (R, &[E, Ee, Se])]),
        "NK" => pattern("NK", &[], &[S], &[(I, &[E, Es]), (R, &[E, Ee])]),
        "KK" => pattern("KK", &[S], &[S], &[(I, &[E, Es, Ss]), (R, &[E, Ee, Se])]),
        "NX" => pattern("NX", &[], &[], &[(I, &[E]), (R, &[E, Ee, S, Es])]),
        "KX" => pattern("KX", &[S], &[], &[(I, &[E]), (R, &[E, Ee, Se, S, Es])]),
        "XN" => pattern("XN", &[], &[], &[(I, &[E]), (R, &[E, Ee]), (I, &[S, Se])]),
        "IN" => pattern("IN", &[], &[], &[(I, &[E, S]), (R, &[E, Ee, Se])]),
        "XK" => pattern(
            "XK",
            &[],
            &[S],
            &[(I, &[E, Es]), (R, &[E, Ee]), (I, &[S, Se])],
        ),
        "IK" => pattern("IK", &[], &[S], &[(I, &[E, Es, S, Ss]), (R, &[E, Ee, Se])]),
        "XX" => pattern(
            "XX",
            &[],
            &[],
            &[(I, &[E]), (R, &[E, Ee, S, Es]), (I, &[S, Se])],
        ),
        "IX" => pattern("IX", &[], &[], &[(I, &[E, S]), (R, &[E, Ee, Se, S, Es])]),
        // ---- one-way patterns -----------------------------------------
        "N" => pattern("N", &[], &[S], &[(I, &[E, Es])]),
        "K" => pattern("K", &[S], &[S], &[(I, &[E, Es, Ss])]),
        "X" => pattern("X", &[], &[S], &[(I, &[E, Es, S, Ss])]),

        // ---- PSK patterns ---------------------------------------------
        "NNpsk0" => pattern("NNpsk0", &[], &[], &[(I, &[Psk, E]), (R, &[E, Ee])]),
        "NNpsk2" => pattern("NNpsk2", &[], &[], &[(I, &[E]), (R, &[E, Ee, Psk])]),
        "NKpsk0" => pattern("NKpsk0", &[], &[S], &[(I, &[Psk, E, Es]), (R, &[E, Ee])]),
        "NKpsk2" => pattern("NKpsk2", &[], &[S], &[(I, &[E, Es]), (R, &[E, Ee, Psk])]),
        "NXpsk2" => pattern("NXpsk2", &[], &[], &[(I, &[E]), (R, &[E, Ee, S, Es, Psk])]),
        "XNpsk3" => pattern(
            "XNpsk3",
            &[],
            &[],
            &[(I, &[E]), (R, &[E, Ee]), (I, &[S, Se, Psk])],
        ),
        "XKpsk3" => pattern(
            "XKpsk3",
            &[],
            &[S],
            &[(I, &[E, Es]), (R, &[E, Ee]), (I, &[S, Se, Psk])],
        ),
        "XXpsk3" => pattern(
            "XXpsk3",
            &[],
            &[],
            &[(I, &[E]), (R, &[E, Ee, S, Es]), (I, &[S, Se, Psk])],
        ),
        "KNpsk0" => pattern("KNpsk0", &[S], &[], &[(I, &[Psk, E]), (R, &[E, Ee, Se])]),
        "KNpsk2" => pattern("KNpsk2", &[S], &[], &[(I, &[E]), (R, &[E, Ee, Se, Psk])]),
        "KKpsk0" => pattern(
            "KKpsk0",
            &[S],
            &[S],
            &[(I, &[Psk, E, Es, Ss]), (R, &[E, Ee, Se])],
        ),
        "KKpsk2" => pattern(
            "KKpsk2",
            &[S],
            &[S],
            &[(I, &[E, Es, Ss]), (R, &[E, Ee, Se, Psk])],
        ),
        "KXpsk2" => pattern(
            "KXpsk2",
            &[S],
            &[],
            &[(I, &[E]), (R, &[E, Ee, Se, S, Es, Psk])],
        ),
        "INpsk1" => pattern("INpsk1", &[], &[], &[(I, &[E, S, Psk]), (R, &[E, Ee, Se])]),
        "INpsk2" => pattern("INpsk2", &[], &[], &[(I, &[E, S]), (R, &[E, Ee, Se, Psk])]),
        "IKpsk1" => pattern(
            "IKpsk1",
            &[],
            &[S],
            &[(I, &[E, Es, S, Ss, Psk]), (R, &[E, Ee, Se])],
        ),
        "IKpsk2" => pattern(
            "IKpsk2",
            &[],
            &[S],
            &[(I, &[E, Es, S, Ss]), (R, &[E, Ee, Se, Psk])],
        ),
        "IXpsk2" => pattern(
            "IXpsk2",
            &[],
            &[],
            &[(I, &[E, S]), (R, &[E, Ee, Se, S, Es, Psk])],
        ),
        "Npsk0" => pattern("Npsk0", &[], &[S], &[(I, &[Psk, E, Es])]),
        "Kpsk0" => pattern("Kpsk0", &[], &[S], &[(I, &[Psk, E, Es, Ss])]),
        "Xpsk1" => pattern("Xpsk1", &[], &[S], &[(I, &[E, Es, S, Ss, Psk])]),
        _ => return None,
    };
    Some(p)
}

/// Returns the names of every supported pattern.
pub fn all_names() -> &'static [&'static str] {
    &[
        "NN", "KN", "NK", "KK", "NX", "KX", "XN", "IN", "XK", "IK", "XX", "IX", "N", "K", "X",
        "NNpsk0", "NNpsk2", "NKpsk0", "NKpsk2", "NXpsk2", "XNpsk3", "XKpsk3", "XXpsk3", "KNpsk0",
        "KNpsk2", "KKpsk0", "KKpsk2", "KXpsk2", "INpsk1", "INpsk2", "IKpsk1", "IKpsk2", "IXpsk2",
        "Npsk0", "Kpsk0", "Xpsk1",
    ]
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tokens = |ts: &[Token]| ts.iter().map(|t| t.as_str()).collect::<Vec<_>>().join(", ");
        if !self.pre_initiator.is_empty() {
            writeln!(f, "  -> {}", tokens(&self.pre_initiator))?;
        }
        if !self.pre_responder.is_empty() {
            writeln!(f, "  <- {}", tokens(&self.pre_responder))?;
        }
        if !self.pre_initiator.is_empty() || !self.pre_responder.is_empty() {
            writeln!(f, "  ...")?;
        }
        for msg in &self.messages {
            let arrow = match msg.sender {
                Role::Initiator => "->",
                Role::Responder => "<-",
            };
            writeln!(f, "  {arrow} {}", tokens(&msg.tokens))?;
        }
        Ok(())
    }
}
