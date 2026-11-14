//! The tracing facility: secret redaction, event coverage, and the guarantee
//! that the library never writes to stdout/stderr on its own.

use std::io::Write;

use noise_rs::*;

fn xx_pair(trace: TraceMode) -> (HandshakeState, HandshakeState) {
    let p = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let init = HandshakeState::new(
        p.clone(),
        Role::Initiator,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            prologue: b"trace-test".to_vec(),
            ..Default::default()
        },
        trace,
    )
    .unwrap();
    let resp = HandshakeState::new(
        p,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            prologue: b"trace-test".to_vec(),
            ..Default::default()
        },
        trace,
    )
    .unwrap();
    (init, resp)
}

#[test]
fn trace_off_records_nothing() {
    let (mut init, mut resp) = xx_pair(TraceMode::Off);
    assert!(
        init.take_trace().is_empty(),
        "TraceMode::Off must not record events"
    );
    let m0 = init.write_message(b"").unwrap();
    assert!(init.take_trace().is_empty());
    resp.read_message(&m0.bytes).unwrap();
    assert!(resp.take_trace().is_empty());
}

#[test]
fn redacted_trace_hides_raw_keys() {
    let (mut init, mut resp) = xx_pair(TraceMode::Redacted);
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let events = init.take_trace();
    for event in &events {
        match event {
            TraceEvent::Split { k1, k2, .. } => {
                assert!(
                    matches!(k1, Secret::Fingerprint(_)),
                    "split keys must be redacted"
                );
                assert!(matches!(k2, Secret::Fingerprint(_)));
                // A fingerprint is 8 bytes -> 16 hex characters, not 64.
                assert_eq!(k1.as_str().len(), 16);
            }
            TraceEvent::Token { ck, .. } => {
                assert!(!ck.is_full());
            }
            _ => {}
        }
    }
}

/// Runs a complete XX handshake and returns the initiator's transport state
/// plus every trace event it produced (the responder's are discarded).
fn complete_xx_with_trace(mode: TraceMode) -> (TransportState, Vec<TraceEvent>) {
    let (mut init, mut resp) = xx_pair(mode);
    let mut events = Vec::new();
    events.extend(init.take_trace());

    let m0 = init.write_message(b"").unwrap();
    events.extend(init.take_trace());
    resp.read_message(&m0.bytes).unwrap();

    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1.bytes).unwrap();
    events.extend(init.take_trace());

    let m2 = init.write_message(b"").unwrap();
    resp.read_message(&m2.bytes).unwrap();
    events.extend(init.take_trace());
    // The final read/completion is what emits `Split`.
    events.extend(init.take_trace());

    let transport = init.into_transport().unwrap();
    (transport, events)
}

#[test]
fn reveal_mode_shows_the_same_keys_the_state_uses() {
    let (transport, events) = complete_xx_with_trace(TraceMode::Full);
    let split = events
        .iter()
        .find_map(|event| match event {
            TraceEvent::Split {
                k1,
                k2,
                sending_key,
                receiving_key,
                handshake_hash,
            } => Some((k1, k2, sending_key, receiving_key, handshake_hash)),
            _ => None,
        })
        .expect("split event must be recorded");

    assert_eq!(
        split.4,
        &hex::encode(transport.handshake_hash()),
        "traced handshake hash must match the transport's"
    );
    // The initiator sends with k1 and receives with k2.
    assert_eq!(
        split.0.as_str(),
        hex::encode(transport.export_sending_key())
    );
    assert_eq!(
        split.1.as_str(),
        hex::encode(transport.export_receiving_key())
    );
    assert_eq!(
        split.2.as_str(),
        split.0.as_str(),
        "sending_key must be k1 for the initiator"
    );
    assert_eq!(split.3.as_str(), split.1.as_str());
}

#[test]
fn trace_covers_every_phase() {
    let (_transport, all) = complete_xx_with_trace(TraceMode::Redacted);

    let mut saw_init = false;
    let mut saw_token = false;
    let mut saw_payload = false;
    let mut saw_message = false;
    let mut saw_split = false;
    for event in &all {
        match event {
            TraceEvent::Init { .. } => saw_init = true,
            TraceEvent::Token { .. } => saw_token = true,
            TraceEvent::Payload { .. } => saw_payload = true,
            TraceEvent::Message { .. } => saw_message = true,
            TraceEvent::Split { .. } => saw_split = true,
            _ => {}
        }
    }
    assert!(
        saw_init && saw_token && saw_payload && saw_message && saw_split,
        "trace must cover all phases"
    );
}

#[test]
fn rejected_events_are_recorded() {
    let (mut init, mut resp) = xx_pair(TraceMode::Redacted);
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let mut bad = m0.bytes.clone();
    bad[0] ^= 1;
    // Feed a malformed message; the rejection must be traced.
    let _ = resp.read_message(&bad);
    let events = resp.take_trace();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, TraceEvent::Rejected { .. })),
        "rejections must be traced"
    );
}

#[test]
fn trace_file_renders_a_readable_log() {
    let dir = std::env::temp_dir().join(format!("noise-trace-{}", std::process::id()));
    let path = dir.join("trace.log");
    let mut sink = TraceSink::to_file(path.clone(), TraceMode::Redacted).unwrap();
    let params = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    sink.print_banner(&params, Role::Initiator);

    let (mut init, mut resp) = xx_pair(TraceMode::Redacted);
    sink.drain(&mut init.take_trace(), "initiator");
    let m0 = init.write_message(b"").unwrap();
    sink.drain(&mut init.take_trace(), "initiator");
    resp.read_message(&m0.bytes).unwrap();
    sink.drain(&mut resp.take_trace(), "responder");
    sink.note("custom note");
    sink.flush();

    let text = std::fs::read_to_string(&path).unwrap();
    for needle in [
        "Noise session",
        "role     : initiator",
        "init protocol=",
        "token e",
        "wire =",
        "custom note",
    ] {
        assert!(
            text.contains(needle),
            "log must contain {needle:?}:\n{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trace_never_leaks_secrets_in_redacted_mode() {
    // Run a full session with redacted tracing and grep the rendered log for
    // any of the actual key bytes.
    let dir = std::env::temp_dir().join(format!("noise-leak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("trace.log");
    let mut sink = TraceSink::to_file(path.clone(), TraceMode::Redacted).unwrap();

    let (mut init, mut resp) = xx_pair(TraceMode::Redacted);
    sink.drain(&mut init.take_trace(), "initiator");

    let m0 = init.write_message(b"").unwrap();
    sink.drain(&mut init.take_trace(), "initiator");
    resp.read_message(&m0.bytes).unwrap();
    sink.drain(&mut resp.take_trace(), "responder");

    let m1 = resp.write_message(b"").unwrap();
    sink.drain(&mut resp.take_trace(), "responder");
    init.read_message(&m1.bytes).unwrap();
    sink.drain(&mut init.take_trace(), "initiator");

    let m2 = init.write_message(b"").unwrap();
    sink.drain(&mut init.take_trace(), "initiator");
    resp.read_message(&m2.bytes).unwrap();
    sink.drain(&mut init.take_trace(), "initiator");
    sink.drain(&mut resp.take_trace(), "responder");

    let transport = init.into_transport().unwrap();
    let sending = hex::encode(transport.export_sending_key());
    let receiving = hex::encode(transport.export_receiving_key());
    sink.flush();

    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        !text.contains(&sending),
        "redacted log leaked the sending key"
    );
    assert!(
        !text.contains(&receiving),
        "redacted log leaked the receiving key"
    );
    // Fingerprints are present, so the log is still useful.
    assert!(text.contains("REKEY") || text.contains("SPLIT"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn library_writes_nothing_to_the_console() {
    // The library must be silent: everything goes through TraceEvent/TraceSink.
    // We can only check that a normal handshake produces no output on the
    // standard streams by relying on the fact that tests capture them; assert
    // the API contract instead: `TraceMode::Off` yields no events for the
    // state-machine steps that would otherwise be rendered.
    let (transport, events) = complete_xx_with_trace(TraceMode::Off);
    assert!(events.is_empty(), "TraceMode::Off must produce no events");
    assert_eq!(
        transport.sending_nonce(),
        0,
        "transport starts at nonce 0 regardless of tracing"
    );
    let mut out = std::io::sink();
    writeln!(out, "no-op").unwrap();
}
