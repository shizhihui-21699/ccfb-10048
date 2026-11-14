//! Transport-phase behaviour: rekey, nonce exhaustion, replay window,
//! out-of-order explicit nonces, and tamper detection.

use noise_rs::*;

fn transport_pair() -> (TransportState, TransportState) {
    let p = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let mut init = HandshakeState::new(
        p.clone(),
        Role::Initiator,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let mut resp = HandshakeState::new(
        p,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1.bytes).unwrap();
    let m2 = init.write_message(b"").unwrap();
    resp.read_message(&m2.bytes).unwrap();
    (
        init.into_transport().unwrap(),
        resp.into_transport().unwrap(),
    )
}

#[test]
fn sequential_transport_roundtrip_many_messages() {
    let (mut init, mut resp) = transport_pair();
    for i in 0..100u32 {
        let msg = format!("message {i}");
        let ct = init.send(msg.as_bytes()).unwrap();
        assert_eq!(resp.receive(&ct).unwrap(), msg.as_bytes());
        assert_eq!(init.sending_nonce(), i as u64 + 1);
        assert_eq!(resp.receiving_nonce(), i as u64 + 1);
    }
}

#[test]
fn replayed_transport_message_fails_sequential_mode() {
    let (mut init, mut resp) = transport_pair();
    let ct = init.send(b"once").unwrap();
    assert_eq!(resp.receive(&ct).unwrap(), b"once");
    // The receiver's nonce advanced, so the replay no longer authenticates.
    match resp.receive(&ct) {
        Err(NoiseError::DecryptionFailed(_)) => {}
        other => panic!("replay must fail, got {other:?}"),
    }
}

#[test]
fn swapped_transport_messages_fail_sequential_mode() {
    let (mut init, mut resp) = transport_pair();
    let a = init.send(b"a").unwrap();
    let b = init.send(b"b").unwrap();
    assert!(
        resp.receive(&b).is_err(),
        "out-of-order ciphertext must not verify"
    );
    // A failed receive does not advance the nonce, so the correct order works.
    assert_eq!(resp.receive(&a).unwrap(), b"a");
    assert_eq!(resp.receive(&b).unwrap(), b"b");
}

#[test]
fn tampered_transport_ciphertext_is_rejected() {
    let (mut init, mut resp) = transport_pair();
    let ct = init.send(b"payload").unwrap();
    for offset in 0..ct.len() {
        let mut bad = ct.clone();
        bad[offset] ^= 0x01;
        assert!(
            resp.receive(&bad).is_err(),
            "tampering byte {offset} must be detected"
        );
        // Reset the receiver's nonce so the next iteration starts clean.
        resp.set_receiving_nonce(0).unwrap();
    }
    assert_eq!(resp.receive(&ct).unwrap(), b"payload");
}

#[test]
fn explicit_nonce_out_of_order_transport_works() {
    let (mut init, mut resp) = transport_pair();
    let c2 = init.send_with_nonce(2, b"two").unwrap();
    let c0 = init.send_with_nonce(0, b"zero").unwrap();
    let c1 = init.send_with_nonce(1, b"one").unwrap();

    // Deliver out of order.
    assert_eq!(resp.receive_with_nonce(2, &c2).unwrap(), b"two");
    assert_eq!(resp.receive_with_nonce(1, &c1).unwrap(), b"one");
    assert_eq!(resp.receive_with_nonce(0, &c0).unwrap(), b"zero");
}

#[test]
fn explicit_nonce_replay_is_rejected() {
    let (mut init, mut resp) = transport_pair();
    let c = init.send_with_nonce(5, b"five").unwrap();
    assert_eq!(resp.receive_with_nonce(5, &c).unwrap(), b"five");
    match resp.receive_with_nonce(5, &c) {
        Err(NoiseError::ReplayDetected) => {}
        other => panic!("explicit-nonce replay must be rejected, got {other:?}"),
    }
}

#[test]
fn explicit_nonce_window_rejects_very_old_messages() {
    let (mut init, mut resp) = transport_pair();
    let old = init.send_with_nonce(0, b"old").unwrap();
    let fresh = init.send_with_nonce(10_000, b"fresh").unwrap();
    // Moving the window far ahead makes nonce 0 fall out of the window.
    assert_eq!(resp.receive_with_nonce(10_000, &fresh).unwrap(), b"fresh");
    assert!(!resp.replay_window_is_fresh(0));
    let err = resp.receive_with_nonce(0, &old).unwrap_err();
    assert!(matches!(err, NoiseError::ReplayDetected), "got {err:?}");
}

#[test]
fn rekey_rotates_keys_and_both_parties_stay_in_sync() {
    let (mut init, mut resp) = transport_pair();
    let ct = init.send(b"before").unwrap();
    assert_eq!(resp.receive(&ct).unwrap(), b"before");

    init.rekey_sending();
    resp.rekey_receiving();
    assert_eq!(init.sending_nonce(), 1, "rekey must not reset the nonce");
    assert_eq!(resp.receiving_nonce(), 1, "rekey must not reset the nonce");

    let ct = init.send(b"after").unwrap();
    assert_eq!(resp.receive(&ct).unwrap(), b"after");

    // The reverse direction must also work after a matched rekey.
    resp.rekey_sending();
    init.rekey_receiving();
    let ct = resp.send(b"reply").unwrap();
    assert_eq!(init.receive(&ct).unwrap(), b"reply");
}

#[test]
fn one_sided_rekey_breaks_decryption() {
    let (mut init, mut resp) = transport_pair();
    let ct = init.send(b"a").unwrap();
    assert_eq!(resp.receive(&ct).unwrap(), b"a");

    init.rekey_sending(); // responder does NOT rekey
    let ct = init.send(b"b").unwrap();
    assert!(
        resp.receive(&ct).is_err(),
        "a one-sided rekey must make the stream unreadable"
    );
}

#[test]
fn rekey_changes_the_actual_key_bytes() {
    let (mut init, _resp) = transport_pair();
    let before = init.export_sending_key();
    init.rekey_sending();
    let after = init.export_sending_key();
    assert_ne!(before, after, "rekey must produce a different key");
}

#[test]
fn nonce_exhaustion_is_detected() {
    let (mut init, mut resp) = transport_pair();
    // The largest usable nonce is 2^64-2; using it is allowed, after which the
    // reserved value 2^64-1 must make every operation fail.
    init.set_sending_nonce(u64::MAX - 1).unwrap();
    let last = init.send(b"last usable nonce").unwrap();
    resp.set_receiving_nonce(u64::MAX - 1).unwrap();
    assert_eq!(resp.receive(&last).unwrap(), b"last usable nonce");

    match init.send(b"one too many") {
        Err(NoiseError::NonceExhausted) => {}
        other => panic!("expected NonceExhausted, got {other:?}"),
    }
    // The reserved nonce cannot be selected either.
    assert!(matches!(
        init.set_sending_nonce(u64::MAX),
        Err(NoiseError::NonceExhausted)
    ));
    assert!(matches!(
        resp.set_receiving_nonce(u64::MAX),
        Err(NoiseError::NonceExhausted)
    ));
}

#[test]
fn rekey_does_not_restore_nonce_capacity() {
    let (mut init, _resp) = transport_pair();
    init.set_sending_nonce(u64::MAX - 1).unwrap();
    init.send(b"last").unwrap();
    init.rekey_sending();
    assert_eq!(init.sending_nonce(), u64::MAX);
    // Section 11.3: rekey keeps `n`, so the session is still exhausted.
    match init.send(b"still exhausted") {
        Err(NoiseError::NonceExhausted) => {}
        other => panic!("expected NonceExhausted after rekey, got {other:?}"),
    }
}

#[test]
fn replay_window_tracks_ordering() {
    let mut window = ReplayWindow::new();
    assert!(window.is_fresh(0));
    window.record(0);
    assert!(!window.is_fresh(0));
    window.record(1);
    window.record(5);
    assert!(!window.is_fresh(1));
    assert!(!window.is_fresh(5));
    assert!(window.is_fresh(2));
    assert!(window.is_fresh(6));
    window.record(2);
    assert!(!window.is_fresh(2));
}

#[test]
fn replay_window_expires_old_nonces() {
    let mut window = ReplayWindow::new();
    window.record(0);
    window.record(10_000);
    assert!(!window.is_fresh(0), "nonce 0 is far outside the window");
    assert!(!window.is_fresh(10_000));
    assert!(window.is_fresh(9_500));
}

#[test]
fn transport_uses_the_right_key_per_direction() {
    let (mut init, mut resp) = transport_pair();
    // A message encrypted with the initiator's sending key must not decrypt
    // with the responder's sending key (i.e. directions are distinct).
    let ct = init.send(b"dir").unwrap();
    let mut wrong = transport_pair().1;
    match wrong.receive(&ct) {
        Err(NoiseError::DecryptionFailed(_)) => {}
        other => panic!("cross-session/misdirected ciphertext must fail, got {other:?}"),
    }
    assert_eq!(resp.receive(&ct).unwrap(), b"dir");
}
