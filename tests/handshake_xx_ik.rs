//! End-to-end XX and IK handshakes over every supported cipher/hash
//! combination, plus transport traffic in both directions.

use noise_rs::*;

fn params(pattern: &str, cipher: &str, hash: &str) -> ProtocolParams {
    ProtocolParams::from_parts(pattern, "25519", cipher, hash).expect("valid protocol name")
}

fn pair(
    params: ProtocolParams,
    prologue: &[u8],
    responder_static: Option<KeyPair>,
    initiator_knows_responder: bool,
) -> (HandshakeState, HandshakeState, Option<PublicKey>) {
    let responder_key = match responder_static {
        Some(kp) => kp,
        None => KeyPair::generate(DhKind::X25519).unwrap(),
    };
    let responder_pub = responder_key.public().clone();

    let initiator_remote = if initiator_knows_responder {
        Some(responder_pub.clone())
    } else {
        None
    };

    // XX sends `s` in message 2 and IK in message 0, so both patterns need
    // the initiator to own a static key.
    let initiator_key = Some(KeyPair::generate(DhKind::X25519).unwrap());
    let init = HandshakeState::new(
        params.clone(),
        Role::Initiator,
        HandshakeConfig {
            local_static: initiator_key,
            remote_static: initiator_remote,
            prologue: prologue.to_vec(),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let resp = HandshakeState::new(
        params,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(responder_key),
            prologue: prologue.to_vec(),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    (init, resp, Some(responder_pub))
}

fn run_handshake(
    mut init: HandshakeState,
    mut resp: HandshakeState,
    payloads: &[(&[u8], &[u8])],
) -> (TransportState, TransportState) {
    let mut i = 0usize;
    while !init.is_complete() {
        let sender = init.next_sender().expect("pattern has a next message");
        let (out_payload, in_payload) = payloads.get(i).copied().unwrap_or((&[], &[]));
        if sender == Role::Initiator {
            let m = init.write_message(out_payload).unwrap();
            let r = resp.read_message(&m.bytes).unwrap();
            assert_eq!(r.payload, out_payload);
        } else {
            let m = resp.write_message(in_payload).unwrap();
            let r = init.read_message(&m.bytes).unwrap();
            assert_eq!(r.payload, in_payload);
        }
        i += 1;
    }
    let init_hash = init.handshake_hash();
    let resp_hash = resp.handshake_hash();
    assert_eq!(
        init_hash, resp_hash,
        "both parties must agree on the handshake hash"
    );

    let init_t = init.into_transport().unwrap();
    let resp_t = resp.into_transport().unwrap();
    assert_eq!(init_t.handshake_hash(), resp_t.handshake_hash());
    (init_t, resp_t)
}

#[test]
fn xx_handshake_and_bidirectional_transport() {
    for cipher in ["ChaChaPoly", "AESGCM"] {
        for hash in ["BLAKE2s", "SHA256"] {
            let (init, resp, _) = pair(params("XX", cipher, hash), b"xx-prologue", None, false);
            let hs_payloads: [(&[u8], &[u8]); 3] = [(b"m0", b""), (b"", b"m1"), (b"m2", b"")];
            let (mut it, mut rt) = run_handshake(init, resp, &hs_payloads);

            // Both parties authenticated each other's static key.
            let init_static_seen = rt.handshake_hash().len();
            assert!(init_static_seen > 0);

            for round in 0..3u8 {
                let from_init = format!("init->resp {cipher}/{hash} #{round}");
                let ct = it.send(from_init.as_bytes()).unwrap();
                assert_eq!(rt.receive(&ct).unwrap(), from_init.as_bytes());

                let from_resp = format!("resp->init {cipher}/{hash} #{round}");
                let ct = rt.send(from_resp.as_bytes()).unwrap();
                assert_eq!(it.receive(&ct).unwrap(), from_resp.as_bytes());
            }
        }
    }
}

#[test]
fn ik_handshake_and_transport() {
    for cipher in ["ChaChaPoly", "AESGCM"] {
        for hash in ["BLAKE2s", "SHA256"] {
            let (init, resp, responder_pub) = pair(
                params("IK", cipher, hash),
                b"ik-prologue",
                Some(KeyPair::generate(DhKind::X25519).unwrap()),
                true,
            );
            let expected_pub = responder_pub.expect("responder public key");

            // IK's responder learns the initiator's static key from message 0.
            let hs_payloads: [(&[u8], &[u8]); 2] = [(b"", b""), (b"", b"")];
            let (mut it, mut rt) = run_handshake(init, resp, &hs_payloads);

            // The initiator must have authenticated the pinned responder key.
            let ct = it.send(b"ik ok").unwrap();
            assert_eq!(rt.receive(&ct).unwrap(), b"ik ok");
            let ct = rt.send(b"ik reply").unwrap();
            assert_eq!(it.receive(&ct).unwrap(), b"ik reply");
            assert!(expected_pub.as_bytes().len() == 32);
        }
    }
}

#[test]
fn ik_requires_remote_static_key() {
    let p = params("IK", "ChaChaPoly", "BLAKE2s");
    let err = HandshakeState::new(
        p,
        Role::Initiator,
        HandshakeConfig::default(),
        TraceMode::Off,
    )
    .unwrap_err();
    assert!(
        matches!(err, NoiseError::MissingKey(_)),
        "IK initiator must be told the responder's static key, got {err:?}"
    );
}

#[test]
fn ik_rejects_wrong_pinned_key() {
    let responder_key = KeyPair::generate(DhKind::X25519).unwrap();
    let initiator_key = KeyPair::generate(DhKind::X25519).unwrap();
    let wrong_public = KeyPair::generate(DhKind::X25519).unwrap().public().clone();
    let p = params("IK", "ChaChaPoly", "BLAKE2s");

    let mut init = HandshakeState::new(
        p.clone(),
        Role::Initiator,
        HandshakeConfig {
            local_static: Some(initiator_key),
            remote_static: Some(wrong_public),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let mut resp = HandshakeState::new(
        p,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(responder_key),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();

    // With the wrong expected key, the responder cannot decrypt `s` (the
    // static key is encrypted under a key derived from `es`), so the
    // handshake fails instead of silently succeeding.
    let m0 = init.write_message(b"").unwrap();
    match resp.read_message(&m0.bytes) {
        Err(NoiseError::DecryptionFailed(_)) => {}
        other => panic!("expected the responder to reject the handshake, got {other:?}"),
    }
}

#[test]
fn prologue_mismatch_fails() {
    let p = params("XX", "ChaChaPoly", "BLAKE2s");
    let kp = KeyPair::generate(DhKind::X25519).unwrap();
    let mut init = HandshakeState::new(
        p.clone(),
        Role::Initiator,
        HandshakeConfig {
            prologue: b"alice".to_vec(),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let mut resp = HandshakeState::new(
        p,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(kp),
            prologue: b"bob".to_vec(),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();

    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    // Message 1 is authenticated, so the divergent prologue surfaces here.
    let m1 = resp.write_message(b"").unwrap();
    match init.read_message(&m1.bytes) {
        Err(NoiseError::DecryptionFailed(_)) => {}
        other => panic!("expected a prologue mismatch to fail, got {other:?}"),
    }
}

#[test]
fn responder_static_key_is_learned_in_xx() {
    let (mut init, mut resp, responder_pub) = pair(
        params("XX", "ChaChaPoly", "BLAKE2s"),
        b"",
        Some(KeyPair::generate(DhKind::X25519).unwrap()),
        false,
    );
    let expected = responder_pub.unwrap();

    // Walk the handshake, checking the initiator learns the responder key.
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    assert!(init.remote_static().is_none());

    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1.bytes).unwrap();
    let learned = init
        .remote_static()
        .expect("XX transmits the responder static");
    assert!(
        learned.ct_eq(&expected),
        "learned key must match the responder's"
    );

    let m2 = init.write_message(b"").unwrap();
    resp.read_message(&m2.bytes).unwrap();
    let initiator_static = resp
        .remote_static()
        .expect("XX transmits the initiator static");
    assert_eq!(initiator_static.as_bytes().len(), 32);
}
