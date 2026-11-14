//! `noise-cli`: a two-party command-line driver for this Noise implementation.
//!
//! It speaks a tiny newline-delimited hex framing over TCP, a pair of files, or
//! stdin/stdout, and prints every handshake message, every token, and every
//! key-derivation step to stderr (or a log file) so a failing handshake can be
//! diagnosed step by step.
//!
//! Run a local session in two terminals:
//!
//! ```text
//! noise-cli serve   --listen 127.0.0.1:9000 --pattern XX --message "hello from server"
//! noise-cli connect --connect 127.0.0.1:9000 --pattern XX --message "hello from client"
//! ```
//!
//! For IK the initiator must know the responder's static public key:
//!
//! ```text
//! # server prints its static key and exits
//! noise-cli serve --pattern IK --print-static-key
//! # then both sides run with that key configured
//! noise-cli serve   --pattern IK --static-key <server-secret-hex>
//! noise-cli connect --pattern IK --remote-static <server-public-hex>
//! ```
//!
//! Framing: each wire frame is one line of lowercase hex. Handshake and
//! transport frames share the format because the phase is implied by the state
//! machine. The single non-hex line `#END` terminates a party's outbound
//! transport stream and is never fed to the AEAD.

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use noise_rs::{
    DhKind, HandshakeConfig, HandshakeState, KeyPair, NoiseError, ProtocolParams, PublicKey, Role,
    TraceMode, TraceSink, TransportState,
};

// ---------------------------------------------------------------------------
// Argument types
// ---------------------------------------------------------------------------

/// Handshake patterns exposed as first-class choices by this tool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum PatternArg {
    /// XX: mutual authentication, forward secrecy, no pre-shared static keys.
    #[value(name = "XX", alias = "xx")]
    Xx,
    /// IK: initiator already knows the responder's static key.
    #[value(name = "IK", alias = "ik")]
    Ik,
}

impl PatternArg {
    fn as_str(self) -> &'static str {
        match self {
            PatternArg::Xx => "XX",
            PatternArg::Ik => "IK",
        }
    }
}

/// AEAD cipher choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum CipherArg {
    /// ChaCha20-Poly1305.
    #[value(name = "ChaChaPoly", alias = "chacha", alias = "chachapoly")]
    Chacha,
    /// AES-256-GCM.
    #[value(name = "AESGCM", alias = "aes", alias = "aesgcm")]
    Aes,
}

impl CipherArg {
    fn as_str(self) -> &'static str {
        match self {
            CipherArg::Chacha => "ChaChaPoly",
            CipherArg::Aes => "AESGCM",
        }
    }
}

/// Hash choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum HashArg {
    /// BLAKE2s-256.
    #[value(name = "BLAKE2s", alias = "blake2s")]
    Blake2s,
    /// SHA-256.
    #[value(name = "SHA256", alias = "sha256")]
    Sha256,
}

impl HashArg {
    fn as_str(self) -> &'static str {
        match self {
            HashArg::Blake2s => "BLAKE2s",
            HashArg::Sha256 => "SHA256",
        }
    }
}

/// Wire transports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum WireArg {
    /// Newline-delimited hex over a TCP connection.
    Tcp,
    /// Newline-delimited hex over a pair of files (FIFOs work well).
    File,
    /// Newline-delimited hex over stdin/stdout.
    Stdio,
}

/// Options shared by both roles.
#[derive(Args, Clone, Debug)]
struct CommonArgs {
    /// Handshake pattern.
    #[arg(long, value_enum, default_value_t = PatternArg::Xx)]
    pattern: PatternArg,

    /// AEAD cipher.
    #[arg(long, value_enum, default_value_t = CipherArg::Chacha)]
    cipher: CipherArg,

    /// Hash function.
    #[arg(long, value_enum, default_value_t = HashArg::Blake2s)]
    hash: HashArg,

    /// DH function (`25519` or `448`).
    #[arg(long, default_value = "25519")]
    dh: String,

    /// Prologue, as a UTF-8 string mixed into the initial hash. Both parties
    /// must use the same value.
    #[arg(long, default_value = "")]
    prologue: String,

    /// Static secret key as hex (32 bytes for 25519, 56 for 448). Generated
    /// when omitted; the public key is printed so the peer can pin it.
    #[arg(long)]
    static_key: Option<String>,

    /// Print this party's static key pair and exit without starting a session.
    /// With `--static-key` it echoes the secret again; without it a fresh key
    /// is generated. Useful for provisioning IK peers.
    #[arg(long)]
    print_static_key: bool,

    /// Reveal raw key bytes in the trace instead of 8-byte fingerprints.
    /// Debugging only -- never use it on a log you would keep.
    #[arg(long)]
    reveal_secrets: bool,

    /// Append the trace to this file rather than stderr.
    #[arg(long)]
    trace_file: Option<PathBuf>,

    /// Print no trace at all (errors still go to stderr).
    #[arg(long)]
    quiet: bool,

    /// Wire transport.
    #[arg(long, value_enum, default_value_t = WireArg::Tcp)]
    wire: WireArg,

    /// Input stream for `--wire file` (defaults to stdin).
    #[arg(long)]
    input: Option<PathBuf>,

    /// Output stream for `--wire file` (defaults to stdout).
    #[arg(long)]
    output: Option<PathBuf>,
}

impl CommonArgs {
    fn protocol_name(&self) -> String {
        format!(
            "Noise_{}_{}_{}_{}",
            self.pattern.as_str(),
            self.dh,
            self.cipher.as_str(),
            self.hash.as_str()
        )
    }

    fn trace_mode(&self) -> TraceMode {
        if self.quiet {
            TraceMode::Off
        } else if self.reveal_secrets {
            TraceMode::Full
        } else {
            TraceMode::Redacted
        }
    }
}

/// Post-handshake behaviour shared by both roles.
#[derive(Args, Clone, Debug)]
struct TransportArgs {
    /// Payload messages to send after the handshake, one per flag.
    #[arg(long = "message", short = 'm')]
    messages: Vec<String>,

    /// Instead of `--message`, read lines from stdin and send each as a
    /// transport message.
    #[arg(long)]
    interactive: bool,

    /// Rotate the sending key every N transport messages sent and the
    /// receiving key every N received (0 disables rekeying). Both peers should
    /// use the same value.
    #[arg(long, default_value_t = 0)]
    rekey_every: u64,

    /// Do not read (or wait for) the peer's transport messages.
    #[arg(long)]
    no_receive: bool,
}

#[derive(Parser, Debug)]
#[command(
    name = "noise-cli",
    about = "Noise handshake driver with step-by-step tracing (XX / IK, 25519/448, ChaChaPoly/AESGCM, BLAKE2s/SHA256)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Act as the initiator and connect to a responder.
    Connect {
        #[command(flatten)]
        common: CommonArgs,

        #[command(flatten)]
        transport: TransportArgs,

        /// Address of the responder (`host:port`).
        #[arg(long, default_value = "127.0.0.1:9000")]
        connect: String,

        /// How long to keep retrying the initial TCP connect, so a client
        /// started at the same time as the server still succeeds.
        #[arg(long, default_value_t = 5000)]
        connect_timeout_ms: u64,

        /// Expected responder static public key, hex. Required by IK; optional
        /// for XX (when given, XX pins the peer's static key).
        #[arg(long)]
        remote_static: Option<String>,

        /// File containing the expected responder static public key, hex.
        #[arg(long)]
        remote_static_file: Option<PathBuf>,
    },

    /// Act as the responder and listen for an initiator.
    Serve {
        #[command(flatten)]
        common: CommonArgs,

        #[command(flatten)]
        transport: TransportArgs,

        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:9000")]
        listen: String,

        /// Handle exactly one connection, then exit.
        #[arg(long)]
        once: bool,

        /// Expected initiator static public key, hex (optional; when given it
        /// is enforced after the handshake).
        #[arg(long)]
        remote_static: Option<String>,

        /// File containing the expected initiator static public key, hex.
        #[arg(long)]
        remote_static_file: Option<PathBuf>,
    },

    /// Print the supported protocol components and exit.
    Algorithms,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), NoiseError> {
    match cli.command {
        Command::Algorithms => {
            print_algorithms();
            Ok(())
        }
        Command::Connect {
            common,
            transport,
            connect,
            connect_timeout_ms,
            remote_static,
            remote_static_file,
        } => {
            let mut sink = TraceSink::open_common(
                common.quiet,
                common.reveal_secrets,
                common.trace_file.as_deref(),
            )?;
            let params = ProtocolParams::parse(&common.protocol_name())?;
            sink.print_banner(&params, Role::Initiator);

            let mut config = build_config(&common, &params)?;
            let pinned_peer = load_public(remote_static, remote_static_file, params.dh)?;
            config.remote_static = match pinned_peer.clone() {
                Some(pk) => Some(pk),
                None if params.pattern.name == "IK" => {
                    return Err(NoiseError::MissingKey(
                        "remote static (IK requires the responder's public key)",
                    ))
                }
                None => None,
            };

            let mut channel: Box<dyn Channel> = match common.wire {
                WireArg::Tcp => {
                    let stream = connect_with_retry(&connect, connect_timeout_ms)?;
                    Box::new(TcpChannel::new(stream)?)
                }
                WireArg::File => Box::new(FileChannel::open(
                    common.input.as_deref(),
                    common.output.as_deref(),
                )?),
                WireArg::Stdio => Box::new(StdioChannel::new()),
            };

            let mut handshake =
                HandshakeState::new(params.clone(), Role::Initiator, config, common.trace_mode())?;
            sink.drain(&mut handshake.take_trace(), "initiator");
            exchange_handshake(&mut handshake, channel.as_mut(), &mut sink, "initiator")?;

            let peer_static = handshake.remote_static().cloned();
            if let (Some(expected), Some(actual)) = (&pinned_peer, &peer_static) {
                if !actual.ct_eq(expected) {
                    let err = NoiseError::InvalidPublicKey(Box::leak(
                        format!(
                            "peer static key mismatch: expected {}, got {}",
                            hex::encode(expected.as_bytes()),
                            hex::encode(actual.as_bytes())
                        )
                        .into_boxed_str(),
                    ));
                    sink.note(&format!("initiator: {err}"));
                    return Err(err);
                }
                sink.note("initiator: peer static key matches the pinned value");
            }
            let transport_state = handshake.into_transport()?;
            let stdout_is_wire = matches!(channel.wire_kind(), WireArg::Stdio);
            finish_session(
                transport_state,
                channel.as_mut(),
                &mut sink,
                "initiator",
                &transport,
                peer_static,
                stdout_is_wire,
            )
        }
        Command::Serve {
            common,
            transport,
            listen,
            once,
            remote_static,
            remote_static_file,
        } => {
            let mut sink = TraceSink::open_common(
                common.quiet,
                common.reveal_secrets,
                common.trace_file.as_deref(),
            )?;
            let params = ProtocolParams::parse(&common.protocol_name())?;
            sink.print_banner(&params, Role::Responder);

            let config_template = build_config(&common, &params)?;
            let expected_peer = load_public(remote_static, remote_static_file, params.dh)?;

            if common.print_static_key {
                let kp = config_template
                    .local_static
                    .as_ref()
                    .ok_or(NoiseError::MissingKey("local static"))?;
                println!("secret {}", hex::encode(kp.secret_bytes()));
                println!("public {}", hex::encode(kp.public().as_bytes()));
                return Ok(());
            }

            match common.wire {
                WireArg::Tcp => {
                    let listener = TcpListener::bind(&listen).map_err(|e| os_error("bind", e))?;
                    sink.note(&format!("listening on {listen}"));
                    loop {
                        let (stream, peer) =
                            listener.accept().map_err(|e| os_error("accept", e))?;
                        sink.note(&format!("connection from {peer}"));
                        let result = serve_one(
                            params.clone(),
                            config_template.clone(),
                            expected_peer.clone(),
                            &common,
                            &transport,
                            Box::new(TcpChannel::new(stream)?),
                            &mut sink,
                        );
                        if let Err(err) = result {
                            eprintln!("session error: {err}");
                        }
                        if once {
                            break;
                        }
                    }
                    Ok(())
                }
                WireArg::File | WireArg::Stdio => {
                    let channel: Box<dyn Channel> = if common.wire == WireArg::File {
                        Box::new(FileChannel::open(
                            common.input.as_deref(),
                            common.output.as_deref(),
                        )?)
                    } else {
                        Box::new(StdioChannel::new())
                    };
                    serve_one(
                        params,
                        config_template,
                        expected_peer,
                        &common,
                        &transport,
                        channel,
                        &mut sink,
                    )
                }
            }
        }
    }
}

fn print_algorithms() {
    println!("Supported protocol-name components");
    println!(
        "  patterns : {}",
        noise_rs::patterns::all_names().join(", ")
    );
    println!("  DH       : 25519, 448");
    println!("  ciphers  : ChaChaPoly, AESGCM");
    println!("  hashes   : BLAKE2s, SHA256, BLAKE2b, SHA512");
    println!();
    println!("Example   : Noise_XX_25519_ChaChaPoly_BLAKE2s");
}

// ---------------------------------------------------------------------------
// Session driving
// ---------------------------------------------------------------------------

fn serve_one(
    params: ProtocolParams,
    config: HandshakeConfig,
    expected_peer: Option<PublicKey>,
    common: &CommonArgs,
    transport: &TransportArgs,
    mut channel: Box<dyn Channel>,
    sink: &mut TraceSink,
) -> Result<(), NoiseError> {
    let mut handshake = HandshakeState::new(params, Role::Responder, config, common.trace_mode())?;
    sink.drain(&mut handshake.take_trace(), "responder");
    exchange_handshake(&mut handshake, channel.as_mut(), sink, "responder")?;

    let peer_static = handshake.remote_static().cloned();
    if let Some(expected) = &expected_peer {
        match &peer_static {
            Some(actual) if actual.ct_eq(expected) => {
                sink.note("responder: peer static key matches the pinned value");
            }
            Some(actual) => {
                let err = NoiseError::InvalidPublicKey(Box::leak(
                    format!(
                        "peer static key mismatch: expected {}, got {}",
                        hex::encode(expected.as_bytes()),
                        hex::encode(actual.as_bytes())
                    )
                    .into_boxed_str(),
                ));
                sink.note(&format!("responder: {err}"));
                return Err(err);
            }
            None => {
                return Err(NoiseError::InvalidState(
                    "this handshake pattern does not transmit a peer static key, \
                     so --remote-static cannot be enforced",
                ))
            }
        }
    }
    let state = handshake.into_transport()?;
    let stdout_is_wire = matches!(channel.wire_kind(), WireArg::Stdio);
    finish_session(
        state,
        channel.as_mut(),
        sink,
        "responder",
        transport,
        peer_static,
        stdout_is_wire,
    )
}

/// Drives the handshake to completion, alternating between the wire and the
/// local state machine according to the pattern.
fn exchange_handshake(
    handshake: &mut HandshakeState,
    channel: &mut dyn Channel,
    sink: &mut TraceSink,
    who: &str,
) -> Result<(), NoiseError> {
    while !handshake.is_complete() {
        let index = handshake.next_message_index();
        let sender = handshake
            .next_sender()
            .ok_or(NoiseError::InvalidState("pattern ran out of messages"))?;
        if sender == handshake.role() {
            sink.step(&format!(
                "{who}: writing handshake message {index} ({})",
                sender
            ));
            let message = handshake.write_message(&[])?;
            sink.drain(&mut handshake.take_trace(), who);
            channel.send_frame(&message.bytes)?;
        } else {
            sink.step(&format!(
                "{who}: reading handshake message {index} ({})",
                sender
            ));
            let frame = channel.recv_frame()?.ok_or(NoiseError::InvalidState(
                "peer closed the connection mid-handshake",
            ))?;
            let received = handshake.read_message(&frame)?;
            sink.drain(&mut handshake.take_trace(), who);
            if !received.payload.is_empty() {
                sink.note(&format!(
                    "{who}: handshake payload ({} bytes): {}",
                    received.payload.len(),
                    display_bytes(&received.payload)
                ));
            }
        }
    }
    sink.step(&format!("{who}: handshake complete"));
    Ok(())
}

fn finish_session(
    mut state: TransportState,
    channel: &mut dyn Channel,
    sink: &mut TraceSink,
    who: &str,
    transport: &TransportArgs,
    peer_static: Option<PublicKey>,
    stdout_is_wire: bool,
) -> Result<(), NoiseError> {
    sink.print_split(&state, peer_static.as_ref());

    let outbound: Vec<Vec<u8>> = if transport.interactive {
        let mut lines = Vec::new();
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let line = line.map_err(|e| os_error("stdin", e))?;
            lines.push(line.into_bytes());
        }
        lines
    } else {
        transport
            .messages
            .iter()
            .map(|m| m.clone().into_bytes())
            .collect()
    };

    // The initiator sends first, then half-closes its outbound stream; the
    // responder drains that stream before replying. This keeps both roles
    // deterministic and deadlock-free regardless of message counts.
    if state.role() == Role::Initiator {
        send_payloads(
            &mut state,
            channel,
            sink,
            who,
            &outbound,
            transport.rekey_every,
        )?;
        channel.end_stream()?;
        receive_payloads(&mut state, channel, sink, who, transport, stdout_is_wire)?;
    } else {
        receive_payloads(&mut state, channel, sink, who, transport, stdout_is_wire)?;
        send_payloads(
            &mut state,
            channel,
            sink,
            who,
            &outbound,
            transport.rekey_every,
        )?;
        channel.end_stream()?;
    }
    Ok(())
}

fn send_payloads(
    state: &mut TransportState,
    channel: &mut dyn Channel,
    sink: &mut TraceSink,
    who: &str,
    payloads: &[Vec<u8>],
    rekey_every: u64,
) -> Result<(), NoiseError> {
    let mut sent = 0u64;
    for payload in payloads {
        let ciphertext = state.send(payload)?;
        sink.drain(&mut state.take_trace(), who);
        channel.send_frame(&ciphertext)?;
        sent += 1;
        if rekey_every > 0 && sent % rekey_every == 0 {
            state.rekey_sending();
            sink.drain(&mut state.take_trace(), who);
        }
    }
    Ok(())
}

fn receive_payloads(
    state: &mut TransportState,
    channel: &mut dyn Channel,
    sink: &mut TraceSink,
    who: &str,
    transport: &TransportArgs,
    stdout_is_wire: bool,
) -> Result<(), NoiseError> {
    if transport.no_receive {
        return Ok(());
    }
    let mut received = 0u64;
    while let Some(frame) = channel.recv_frame()? {
        match state.receive(&frame) {
            Ok(plaintext) => {
                // stdout carries the wire frames for `--wire stdio`; printing
                // received payloads there would corrupt the framing.
                if stdout_is_wire {
                    sink.note(&format!("{who}: received {}", display_bytes(&plaintext)));
                } else {
                    println!("{}  {}", who, display_bytes(&plaintext));
                }
                sink.drain(&mut state.take_trace(), who);
                received += 1;
                if transport.rekey_every > 0 && received % transport.rekey_every == 0 {
                    state.rekey_receiving();
                    sink.drain(&mut state.take_trace(), who);
                }
            }
            Err(err) => {
                sink.drain(&mut state.take_trace(), who);
                sink.note(&format!("{who}: rejected transport message: {err}"));
                return Err(err);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration / key loading
// ---------------------------------------------------------------------------

fn build_config(
    common: &CommonArgs,
    params: &ProtocolParams,
) -> Result<HandshakeConfig, NoiseError> {
    let local_static = match &common.static_key {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|_| NoiseError::InvalidState("--static-key is not valid hex"))?;
            Some(KeyPair::from_secret(params.dh, &bytes)?)
        }
        None => Some(KeyPair::generate(params.dh)?),
    };

    Ok(HandshakeConfig {
        local_static,
        remote_static: None,
        local_ephemeral: None,
        remote_ephemeral: None,
        psk: None,
        prologue: common.prologue.clone().into_bytes(),
    })
}

fn load_public(
    inline: Option<String>,
    file: Option<PathBuf>,
    dh: DhKind,
) -> Result<Option<PublicKey>, NoiseError> {
    let hex_value = match (inline, file) {
        (Some(v), _) => Some(v),
        (None, Some(path)) => Some(
            std::fs::read_to_string(&path)
                .map_err(|e| os_error("read public key file", e))?
                .trim()
                .to_owned(),
        ),
        (None, None) => None,
    };
    match hex_value {
        None => Ok(None),
        Some(v) => {
            let bytes = hex::decode(v.trim())
                .map_err(|_| NoiseError::InvalidState("public key is not valid hex"))?;
            PublicKey::from_bytes(dh, &bytes).map(Some)
        }
    }
}

/// Connects, retrying until the deadline, so a client can be started in
/// parallel with its server.
fn connect_with_retry(addr: &str, timeout_ms: u64) -> Result<TcpStream, NoiseError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) if std::time::Instant::now() >= deadline => {
                return Err(os_error("connect", err));
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(40)),
        }
    }
}

fn os_error(what: &'static str, err: io::Error) -> NoiseError {
    NoiseError::InvalidState(Box::leak(format!("{what}: {err}").into_boxed_str()))
}

fn display_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) if s.chars().all(|c| !c.is_control() || c == '\t') => format!("{s:?}"),
        _ => format!("<{} bytes hex {}>", bytes.len(), hex::encode(bytes)),
    }
}

// ---------------------------------------------------------------------------
// Wire channels
// ---------------------------------------------------------------------------

/// A framed byte channel. Each frame is one line of lowercase hex; the frame
/// `#END` marks the end of a party's outbound stream.
trait Channel {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<(), NoiseError>;
    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NoiseError>;
    fn end_stream(&mut self) -> Result<(), NoiseError>;

    /// Which transport this channel speaks, so callers can avoid writing
    /// human-readable output into a wire stream.
    fn wire_kind(&self) -> WireArg;
}

const END_FRAME: &str = "#END";

fn encode_frame(bytes: &[u8]) -> Vec<u8> {
    let mut line = hex::encode(bytes).into_bytes();
    line.push(b'\n');
    line
}

fn is_end_frame(line: &str) -> bool {
    line.trim() == END_FRAME
}

struct TcpChannel {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
}

impl TcpChannel {
    fn new(stream: TcpStream) -> Result<Self, NoiseError> {
        let writer_stream = stream
            .try_clone()
            .map_err(|e| os_error("clone stream", e))?;
        Ok(TcpChannel {
            reader: BufReader::new(stream),
            writer: BufWriter::new(writer_stream),
        })
    }
}

impl Channel for TcpChannel {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<(), NoiseError> {
        self.writer
            .write_all(&encode_frame(bytes))
            .and_then(|_| self.writer.flush())
            .map_err(|e| os_error("write", e))
    }

    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        read_frame(&mut self.reader)
    }

    fn wire_kind(&self) -> WireArg {
        WireArg::Tcp
    }

    fn end_stream(&mut self) -> Result<(), NoiseError> {
        self.writer
            .write_all(format!("{END_FRAME}\n").as_bytes())
            .and_then(|_| self.writer.flush())
            .map_err(|e| os_error("write", e))
    }
}

/// Reads one frame from a line-oriented reader.
fn read_frame<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, NoiseError> {
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| os_error("read", e))?;
        if n == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_end_frame(trimmed) {
            return Ok(None);
        }
        return hex::decode(trimmed)
            .map(Some)
            .map_err(|_| NoiseError::InvalidState("received a frame that is not valid hex"));
    }
}

struct FileChannel {
    reader: Option<BufReader<File>>,
    writer: Option<BufWriter<File>>,
}

impl FileChannel {
    fn open(input: Option<&Path>, output: Option<&Path>) -> Result<Self, NoiseError> {
        let reader = match input {
            Some(path) => Some(BufReader::new(
                File::open(path).map_err(|e| os_error("open input", e))?,
            )),
            None => None,
        };
        let writer = match output {
            Some(path) => Some(BufWriter::new(
                File::create(path).map_err(|e| os_error("open output", e))?,
            )),
            None => None,
        };
        Ok(FileChannel { reader, writer })
    }
}

impl Channel for FileChannel {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<(), NoiseError> {
        let writer = self
            .writer
            .as_mut()
            .ok_or(NoiseError::NotAvailable("no --output file"))?;
        writer
            .write_all(&encode_frame(bytes))
            .and_then(|_| writer.flush())
            .map_err(|e| os_error("write", e))
    }

    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        let reader = self
            .reader
            .as_mut()
            .ok_or(NoiseError::NotAvailable("no --input file"))?;
        read_frame(reader)
    }

    fn wire_kind(&self) -> WireArg {
        WireArg::File
    }

    fn end_stream(&mut self) -> Result<(), NoiseError> {
        if let Some(writer) = self.writer.as_mut() {
            writer
                .write_all(format!("{END_FRAME}\n").as_bytes())
                .and_then(|_| writer.flush())
                .map_err(|e| os_error("write", e))?;
        }
        Ok(())
    }
}

struct StdioChannel {
    reader: BufReader<io::Stdin>,
    writer: BufWriter<io::Stdout>,
}

impl StdioChannel {
    fn new() -> Self {
        StdioChannel {
            reader: BufReader::new(io::stdin()),
            writer: BufWriter::new(io::stdout()),
        }
    }
}

impl Channel for StdioChannel {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<(), NoiseError> {
        self.writer
            .write_all(&encode_frame(bytes))
            .and_then(|_| self.writer.flush())
            .map_err(|e| os_error("write", e))
    }

    fn recv_frame(&mut self) -> Result<Option<Vec<u8>>, NoiseError> {
        read_frame(&mut self.reader)
    }

    fn wire_kind(&self) -> WireArg {
        WireArg::Stdio
    }

    fn end_stream(&mut self) -> Result<(), NoiseError> {
        self.writer
            .write_all(format!("{END_FRAME}\n").as_bytes())
            .and_then(|_| self.writer.flush())
            .map_err(|e| os_error("write", e))
    }
}
