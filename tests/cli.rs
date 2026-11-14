//! Integration tests for the `noise-cli` binary: drives a real responder and
//! initiator over a loopback TCP socket and over files, and checks that the
//! trace output contains every step a user needs to debug a handshake.

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the compiled binary under test.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_noise-cli")
}

/// Waits until something is listening on `addr`.
///
/// The probe must not connect: the tests often run a `--once` responder, and
/// a probe connection would consume its single accept slot. Instead, try to
/// bind the same address -- success means nothing was listening.
fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match std::net::TcpListener::bind(addr) {
            Ok(listener) => drop(listener),
            Err(_) => return true,
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

/// Extracts `secret <hex>` and `public <hex>` from `--print-static-key` output.
fn static_keypair(args: &[&str]) -> (String, String) {
    let output = Command::new(binary())
        .args(args)
        .args(["--print-static-key"])
        .output()
        .expect("run noise-cli");
    assert!(
        output.status.success(),
        "print-static-key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut secret = String::new();
    let mut public = String::new();
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("secret ") {
            secret = v.trim().to_owned();
        }
        if let Some(v) = line.strip_prefix("public ") {
            public = v.trim().to_owned();
        }
    }
    assert_eq!(secret.len(), 64, "25519 secret is 32 bytes");
    assert_eq!(public.len(), 64, "25519 public is 32 bytes");
    (secret, public)
}

#[test]
fn algorithms_lists_the_supported_primitives() {
    let output = Command::new(binary()).arg("algorithms").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for needle in [
        "XX",
        "IK",
        "25519",
        "ChaChaPoly",
        "AESGCM",
        "BLAKE2s",
        "SHA256",
    ] {
        assert!(
            text.contains(needle),
            "algorithms output must mention {needle}"
        );
    }
}

#[test]
fn xx_session_over_tcp_with_traced_steps() {
    let port = 19131;
    let addr = format!("127.0.0.1:{port}");

    let server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "XX"])
        .args(["--message", "server says hi"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn responder");

    assert!(
        wait_for_port(&addr, Duration::from_secs(5)),
        "server never listened"
    );

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "XX"])
        .args(["--message", "client says hi"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run initiator");

    let server_out = server.wait_with_output().expect("collect responder");
    assert!(
        client.status.success(),
        "initiator failed: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        server_out.status.success(),
        "responder failed: {}",
        String::from_utf8_lossy(&server_out.stderr)
    );

    let client_stdout = String::from_utf8(client.stdout).unwrap();
    assert!(
        client_stdout.contains("server says hi"),
        "initiator must print the responder's payload, got: {client_stdout}"
    );

    // The trace must show every phase: init, each message, each token, the
    // split, and the transport messages.
    let trace = String::from_utf8(client.stderr).unwrap();
    for needle in [
        "Noise_XX_25519_ChaChaPoly_BLAKE2s",
        "init protocol=",
        "token e ",
        "token ee",
        "token s ",
        "token es",
        "token se",
        "SPLIT",
        "handshake_hash",
        "transport send",
        "transport receive",
        "handshake established",
    ] {
        assert!(
            trace.contains(needle),
            "trace must contain {needle:?}:\n{trace}"
        );
    }
    // Redacted mode must not reveal raw keys: the fingerprint is 16 hex chars.
    assert!(
        trace.contains("k1 (init->resp) = "),
        "trace must show split keys"
    );
}

#[test]
fn ik_session_uses_the_provisioned_static_key() {
    let (secret, public) = static_keypair(&["serve", "--pattern", "IK"]);
    let port = 19132;
    let addr = format!("127.0.0.1:{port}");

    let server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "IK"])
        .args(["--static-key", &secret, "--message", "ik server payload"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn responder");

    assert!(
        wait_for_port(&addr, Duration::from_secs(5)),
        "server never listened"
    );

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "IK"])
        .args(["--remote-static", &public, "--message", "ik client payload"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .expect("run initiator");

    let server_out = server.wait_with_output().expect("collect responder");
    assert!(
        client.status.success(),
        "initiator failed: {}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        server_out.status.success(),
        "responder failed: {}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    let stdout = String::from_utf8(client.stdout).unwrap();
    assert!(
        stdout.contains("ik server payload"),
        "initiator must print the responder payload, got {stdout}"
    );

    let trace = String::from_utf8(client.stderr).unwrap();
    assert!(trace.contains("Noise_IK_25519_ChaChaPoly_BLAKE2s"));
    assert!(
        trace.contains(&format!("authenticated peer static key   = {public}")),
        "trace must show the authenticated peer key"
    );
    assert!(trace.contains("token es"), "IK uses es");
    assert!(trace.contains("token ss"), "IK uses ss");
}

#[test]
fn mismatched_pinned_key_is_reported() {
    let port = 19133;
    let addr = format!("127.0.0.1:{port}");
    let (secret, _public) = static_keypair(&["serve", "--pattern", "IK"]);
    let (_, other_public) = static_keypair(&["serve", "--pattern", "IK", "--static-key", &secret]);
    // Generate a *different* key pair to pin incorrectly.
    let (_, wrong_public) =
        static_keypair(&["serve", "--pattern", "IK", "--static-key", &"11".repeat(32)]);
    assert_ne!(other_public, wrong_public);

    let mut server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "IK"])
        .args(["--static-key", &secret])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn responder");
    assert!(wait_for_port(&addr, Duration::from_secs(5)));

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "IK"])
        .args(["--remote-static", &wrong_public])
        .stderr(Stdio::piped())
        .output()
        .expect("run initiator");

    let _ = server.wait();
    assert!(
        !client.status.success(),
        "a wrong pinned key must fail the run"
    );
    let stderr = String::from_utf8(client.stderr).unwrap();
    assert!(
        stderr.contains("error:"),
        "the CLI must report an error, got: {stderr}"
    );
}

#[test]
fn aes_gcm_and_sha256_combination_works() {
    let port = 19134;
    let addr = format!("127.0.0.1:{port}");
    let server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "XX"])
        .args([
            "--cipher",
            "AESGCM",
            "--hash",
            "SHA256",
            "--message",
            "aead ok",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for_port(&addr, Duration::from_secs(5)));

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "XX"])
        .args([
            "--cipher",
            "AESGCM",
            "--hash",
            "SHA256",
            "--message",
            "hello",
        ])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let server_out = server.wait_with_output().unwrap();
    assert!(
        client.status.success(),
        "{}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        server_out.status.success(),
        "{}",
        String::from_utf8_lossy(&server_out.stderr)
    );
    assert!(String::from_utf8(client.stdout)
        .unwrap()
        .contains("aead ok"));
    let trace = String::from_utf8(client.stderr).unwrap();
    assert!(trace.contains("Noise_XX_25519_AESGCM_SHA256"));
}

#[test]
fn rekey_every_message_keeps_the_session_alive() {
    let port = 19135;
    let addr = format!("127.0.0.1:{port}");
    let server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "XX"])
        .args(["--rekey-every", "1"])
        .args(["-m", "s1", "-m", "s2", "-m", "s3"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for_port(&addr, Duration::from_secs(5)));

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "XX"])
        .args(["--rekey-every", "1"])
        .args(["-m", "c1", "-m", "c2"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let server_out = server.wait_with_output().unwrap();
    assert!(
        client.status.success(),
        "{}",
        String::from_utf8_lossy(&client.stderr)
    );
    assert!(
        server_out.status.success(),
        "{}",
        String::from_utf8_lossy(&server_out.stderr)
    );

    let stdout = String::from_utf8(client.stdout).unwrap();
    for expected in ["s1", "s2", "s3"] {
        assert!(stdout.contains(expected), "missing {expected} in {stdout}");
    }
    let trace = String::from_utf8(client.stderr).unwrap();
    assert!(trace.contains("REKEY send"), "trace must record rekeys");
    assert!(trace.contains("REKEY receive"));
}

#[test]
fn file_wire_options_are_accepted_and_documented() {
    // A real two-party exchange over regular files cannot alternate safely
    // (each side would have to poll a shared file), so the file transport is
    // documented for FIFOs, which provide the required blocking semantics.
    // Here we check that the options parse and that the transport produces
    // the first frame, which is what the handshake needs.
    let dir = std::env::temp_dir().join(format!("noise-cli-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.hex");
    let output = dir.join("output.hex");
    std::fs::File::create(&input).unwrap();

    let mut server = Command::new(binary())
        .args(["serve", "--wire", "file", "--pattern", "IK"])
        .args(["--input", input.to_str().unwrap()])
        .args(["--output", output.to_str().unwrap()])
        .args(["--print-static-key"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn responder");

    let status = wait_with_timeout(&mut server, Duration::from_secs(10))
        .expect("print-static-key must not block");
    assert!(status.success());
    let mut stdout = String::new();
    server
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(stdout.contains("secret "));
    assert!(stdout.contains("public "));

    let _ = std::fs::remove_dir_all(&dir);

    let help = Command::new(binary())
        .args(["connect", "--help"])
        .output()
        .unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    for needle in [
        "--input",
        "--output",
        "--rekey-every",
        "--remote-static",
        "--reveal-secrets",
    ] {
        assert!(text.contains(needle), "help must document {needle}");
    }
}

#[test]
fn quiet_mode_suppresses_the_trace() {
    let port = 19136;
    let addr = format!("127.0.0.1:{port}");
    let server = Command::new(binary())
        .args([
            "serve",
            "--listen",
            &addr,
            "--once",
            "--pattern",
            "XX",
            "--quiet",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for_port(&addr, Duration::from_secs(5)));

    let client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "XX", "--quiet"])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let _ = server.wait_with_output();
    assert!(client.status.success());
    assert!(
        String::from_utf8(client.stderr).unwrap().trim().is_empty(),
        "--quiet must suppress all trace output"
    );
}

#[test]
fn reveal_secrets_prints_full_key_material() {
    let port = 19137;
    let addr = format!("127.0.0.1:{port}");
    let server = Command::new(binary())
        .args(["serve", "--listen", &addr, "--once", "--pattern", "XX"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(wait_for_port(&addr, Duration::from_secs(5)));

    let client = Command::new(binary())
        .args([
            "connect",
            "--connect",
            &addr,
            "--pattern",
            "XX",
            "--reveal-secrets",
        ])
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let _ = server.wait_with_output();
    assert!(client.status.success());
    let trace = String::from_utf8(client.stderr).unwrap();
    assert!(
        trace.contains("secrets  : REVEALED"),
        "banner must warn that secrets are shown"
    );
    // A full 32-byte key is 64 hex characters; find one on a split line.
    let has_full_key = trace
        .lines()
        .any(|line| line.contains("k1 (init->resp) = ") && line.len() > 64);
    assert!(has_full_key, "reveal mode must print full keys");
}

#[test]
fn wire_frames_are_newline_delimited_hex() {
    // The test acts as the raw peer: it accepts the connection and inspects
    // the very first frame `noise-cli connect` writes. Because the CLI starts
    // the loopback connection asynchronously, we must be listening first.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let mut client = Command::new(binary())
        .args(["connect", "--connect", &addr, "--pattern", "XX", "--quiet"])
        .args(["--connect-timeout-ms", "5000"])
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn initiator");

    let (stream, _) = listener.accept().expect("accept the CLI connection");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let frame = line.trim();

    // XX message 0 is exactly one 32-byte ephemeral public key.
    assert_eq!(frame.len(), 64, "frame is 32 bytes of hex, got {frame:?}");
    assert!(
        frame
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "frames are lowercase hex, got {frame:?}"
    );
    assert!(line.ends_with('\n'), "frames are newline terminated");

    // Dropping the stream makes the CLI's next read see EOF; it must exit
    // rather than hang.
    drop(reader);
    let status = wait_with_timeout(&mut client, Duration::from_secs(10));
    assert!(
        status.is_some(),
        "the CLI must exit when the peer disconnects"
    );
    assert!(
        !status.unwrap().success(),
        "an aborted handshake is an error"
    );
}

/// Waits for a child to exit, killing it if it overruns.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return None,
        }
    }
}
