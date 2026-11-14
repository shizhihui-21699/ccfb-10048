//! Human-readable rendering of [`TraceEvent`]s.
//!
//! [`TraceSink`] is the bridge between the library's structured trace and a
//! terminal or log file. The CLI uses it; library users can use it too, or
//! match on [`TraceEvent`] directly.

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::error::NoiseError;
use crate::patterns::{Role, Token};
use crate::trace::{Secret, TraceEvent, TraceMode};
use crate::transport::TransportState;

/// Where trace output is written.
enum Destination {
    /// Standard error.
    Stderr,
    /// An appended file.
    File(BufWriter<std::fs::File>),
    /// Discard everything.
    Discard,
}

/// Renders trace events with stable, greppable formatting.
pub struct TraceSink {
    dest: Destination,
    mode: TraceMode,
    /// Number of events rendered, for the closing summary.
    events: usize,
}

impl std::fmt::Debug for TraceSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceSink")
            .field("mode", &self.mode)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl TraceSink {
    /// Builds a sink from CLI-style options.
    ///
    /// * `quiet` disables all output.
    /// * `reveal_secrets` selects [`TraceMode::Full`].
    /// * `file` redirects output from stderr to a file (created/appended).
    pub fn open_common(
        quiet: bool,
        reveal_secrets: bool,
        file: Option<&Path>,
    ) -> Result<Self, NoiseError> {
        let mode = if quiet {
            TraceMode::Off
        } else if reveal_secrets {
            TraceMode::Full
        } else {
            TraceMode::Redacted
        };
        let dest = if quiet {
            Destination::Discard
        } else {
            match file {
                Some(path) => {
                    if let Some(parent) = path.parent() {
                        if !parent.as_os_str().is_empty() {
                            std::fs::create_dir_all(parent).map_err(|e| {
                                NoiseError::InvalidState(Box::leak(
                                    format!("create trace directory {}: {e}", parent.display())
                                        .into_boxed_str(),
                                ))
                            })?;
                        }
                    }
                    let f = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .map_err(|e| {
                            NoiseError::InvalidState(Box::leak(
                                format!("open trace file: {e}").into_boxed_str(),
                            ))
                        })?;
                    Destination::File(BufWriter::new(f))
                }
                None => Destination::Stderr,
            }
        };
        Ok(TraceSink {
            dest,
            mode,
            events: 0,
        })
    }

    /// Creates a sink that writes to stderr with the given mode.
    pub fn to_stderr(mode: TraceMode) -> Self {
        TraceSink {
            dest: if mode == TraceMode::Off {
                Destination::Discard
            } else {
                Destination::Stderr
            },
            mode,
            events: 0,
        }
    }

    /// Creates a sink that appends to `path`, creating any missing parent
    /// directories.
    pub fn to_file(path: PathBuf, mode: TraceMode) -> Result<Self, NoiseError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NoiseError::InvalidState(Box::leak(
                        format!("create trace directory {}: {e}", parent.display())
                            .into_boxed_str(),
                    ))
                })?;
            }
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                NoiseError::InvalidState(Box::leak(
                    format!("open trace file {}: {e}", path.display()).into_boxed_str(),
                ))
            })?;
        Ok(TraceSink {
            dest: Destination::File(BufWriter::new(f)),
            mode,
            events: 0,
        })
    }

    /// The selected trace mode.
    pub fn mode(&self) -> TraceMode {
        self.mode
    }

    /// Number of events rendered so far.
    pub fn event_count(&self) -> usize {
        self.events
    }

    /// Writes a free-form note.
    pub fn note(&mut self, message: &str) {
        self.write_line(&format!("· {message}"));
    }

    /// Writes a step header.
    pub fn step(&mut self, message: &str) {
        self.write_line(&format!("▸ {message}"));
    }

    /// Prints the negotiated parameters and the pattern diagram.
    pub fn print_banner(&mut self, params: &crate::params::ProtocolParams, role: Role) {
        let name = String::from_utf8_lossy(&params.protocol_name()).into_owned();
        self.write_line("═══ Noise session ═══");
        self.write_line(&format!("  role     : {role}"));
        self.write_line(&format!("  protocol : {name}"));
        self.write_line("  pattern  :");
        for line in params.pattern.to_string().lines() {
            self.write_line(&format!("    {line}"));
        }
        if self.mode == TraceMode::Full {
            self.write_line("  secrets  : REVEALED (--reveal-secrets)");
        }
    }

    /// Renders every pending event from a state object.
    pub fn drain(&mut self, events: &mut Vec<TraceEvent>, who: &str) {
        for event in events.drain(..) {
            self.render(&event, who);
        }
    }

    /// Renders a single event.
    pub fn render(&mut self, event: &TraceEvent, who: &str) {
        self.events += 1;
        match event {
            TraceEvent::Init {
                protocol_name,
                role,
                psk_mode,
                prologue,
                h,
                ck,
            } => {
                self.write_line(&format!(
                    "  [{who}] init protocol={protocol_name} role={role} psk={psk_mode}"
                ));
                self.write_line(&format!("        prologue = {}", hex_or_empty(prologue)));
                self.write_line(&format!("        h  = {h}"));
                self.write_line(&format!("        ck = {}", ck.as_str()));
            }
            TraceEvent::PreMessage {
                sender,
                token,
                public_key,
                h,
            } => {
                self.write_line(&format!(
                    "  [{who}] pre-message {} from {sender} ({})",
                    token.as_str(),
                    short(public_key)
                ));
                self.write_line(&format!("        h  = {h}"));
            }
            TraceEvent::Message {
                index,
                sender,
                direction,
                payload_len,
                wire_len,
                wire,
            } => {
                self.write_line(&format!(
                    "  [{who}] {direction} handshake msg #{index} from {sender} \
                     ({payload_len} byte payload, {wire_len} bytes on the wire)"
                ));
                self.write_line(&format!("        wire = {}", truncate_hex(wire, 96)));
            }
            TraceEvent::Token {
                index,
                token,
                details,
                h,
                ck,
                has_key,
                nonce,
            } => {
                let token_name = token_label(*token);
                self.write_line(&format!(
                    "  [{who}] msg #{index} token {token_name}{}",
                    if *has_key {
                        format!(" (key set, n={nonce})")
                    } else {
                        " (no key yet)".to_owned()
                    }
                ));
                for (key, value) in details {
                    self.write_line(&format!("        {key} = {}", truncate_hex(value, 96)));
                }
                self.write_line(&format!("        h  = {h}"));
                self.write_line(&format!("        ck = {}", ck.as_str()));
            }
            TraceEvent::Payload {
                index,
                direction,
                nonce,
                ad,
                key,
                input_len,
                output_len,
                bytes,
                ok,
                h_after,
            } => {
                let nonce = nonce
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                self.write_line(&format!(
                    "  [{who}] msg #{index} payload {direction}: {input_len} -> {output_len} bytes \
                     (n={nonce}, ok={ok})"
                ));
                self.write_line(&format!("        ad  = {}", truncate_hex(ad, 96)));
                self.write_line(&format!("        key = {}", key.as_str()));
                self.write_line(&format!("        ct  = {}", truncate_hex(bytes, 96)));
                self.write_line(&format!("        h   = {h_after}"));
            }
            TraceEvent::Split {
                handshake_hash,
                k1,
                k2,
                sending_key,
                receiving_key,
            } => {
                self.write_line(&format!(
                    "  [{who}] SPLIT: handshake complete, transport keys derived"
                ));
                self.write_line(&format!("        handshake_hash = {handshake_hash}"));
                self.write_line(&format!("        k1 (init->resp) = {}", k1.as_str()));
                self.write_line(&format!("        k2 (resp->init) = {}", k2.as_str()));
                self.write_line(&format!("        sending  = {}", sending_key.as_str()));
                self.write_line(&format!("        receiving= {}", receiving_key.as_str()));
            }
            TraceEvent::TransportSend {
                nonce,
                key,
                plaintext_len,
                bytes,
            } => {
                self.write_line(&format!(
                    "  [{who}] transport send n={nonce} ({plaintext_len} bytes plaintext)"
                ));
                self.write_line(&format!("        key = {}", key.as_str()));
                self.write_line(&format!("        ct  = {}", truncate_hex(bytes, 96)));
            }
            TraceEvent::TransportReceive {
                nonce,
                key,
                ciphertext_len,
                plaintext_len,
                ok,
                explicit,
            } => {
                let nonce = nonce
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_owned());
                self.write_line(&format!(
                    "  [{who}] transport receive n={nonce} ({ciphertext_len} bytes, explicit={explicit}, ok={ok})"
                ));
                self.write_line(&format!("        key = {}", key.as_str()));
                if let Some(len) = plaintext_len {
                    self.write_line(&format!("        plaintext = {len} bytes"));
                }
            }
            TraceEvent::Rekey {
                direction,
                nonce,
                old_key,
                new_key,
            } => {
                self.write_line(&format!("  [{who}] REKEY {direction} (n stays {nonce})"));
                self.write_line(&format!("        old = {}", old_key.as_str()));
                self.write_line(&format!("        new = {}", new_key.as_str()));
            }
            TraceEvent::Rejected { operation, reason } => {
                self.write_line(&format!("  [{who}] REJECTED {operation}: {reason}"));
            }
        }
    }

    /// Prints the final state of a completed handshake.
    pub fn print_split(&mut self, state: &TransportState, peer: Option<&crate::crypto::PublicKey>) {
        self.write_line("─── handshake established ───");
        self.write_line(&format!(
            "  handshake hash (channel binding) = {}",
            hex::encode(state.handshake_hash())
        ));
        if let Some(peer) = peer {
            self.write_line(&format!(
                "  authenticated peer static key   = {}",
                hex::encode(peer.as_bytes())
            ));
        } else {
            self.write_line(
                "  authenticated peer static key   = <not transmitted by this pattern>",
            );
        }
        self.write_line(&format!(
            "  sending nonce (next)            = {}",
            state.sending_nonce()
        ));
        self.write_line(&format!(
            "  receiving nonce (next)          = {}",
            state.receiving_nonce()
        ));
        self.write_line("");
    }

    /// Flushes any buffered output.
    pub fn flush(&mut self) {
        match &mut self.dest {
            Destination::Stderr => {
                let _ = io::stderr().flush();
            }
            Destination::File(w) => {
                let _ = w.flush();
            }
            Destination::Discard => {}
        }
    }

    fn write_line(&mut self, line: &str) {
        let result = match &mut self.dest {
            Destination::Stderr => {
                let mut err = io::stderr().lock();
                writeln!(err, "{line}")
            }
            Destination::File(w) => writeln!(w, "{line}"),
            Destination::Discard => Ok(()),
        };
        if result.is_ok() {
            // Keep the line-buffered destination in sync so a crash cannot lose
            // the last few steps.
            if let Destination::File(w) = &mut self.dest {
                let _ = w.flush();
            }
        }
    }
}

fn hex_or_empty(value: &str) -> String {
    if value.is_empty() {
        "<empty>".to_owned()
    } else {
        value.to_owned()
    }
}

fn short(value: &str) -> String {
    if value.len() <= 32 {
        value.to_owned()
    } else {
        format!("{}…", &value[..32])
    }
}

fn truncate_hex(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_owned()
    } else {
        format!("{}… ({} hex chars)", &value[..max], value.len())
    }
}

fn token_label(token: Token) -> &'static str {
    match token {
        Token::E => "e      (ephemeral public key)",
        Token::S => "s      (encrypted static public key)",
        Token::Ee => "ee     (DH(e, re))",
        Token::Es => "es     (DH(e, rs) / DH(s, re))",
        Token::Se => "se     (DH(s, re) / DH(e, rs))",
        Token::Ss => "ss     (DH(s, rs))",
        Token::Psk => "psk    (MixKeyAndHash)",
    }
}

/// Convenience re-export for tests that want to assert on secrets.
pub fn secret_is_redacted(secret: &Secret) -> bool {
    matches!(secret, Secret::Fingerprint(_))
}
