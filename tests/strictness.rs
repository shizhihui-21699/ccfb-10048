//! Strict state-machine behaviour: wrong direction, reordering, replay,
//! poisoning, truncation, oversized messages, invalid keys.

use noise_rs::*;

fn xx_pair() -> (HandshakeState, HandshakeState) {
    let p = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let init = HandshakeState::new(
        p.clone(),
        Role::Initiator,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    let resp = HandshakeState::new(
        p,
        Role::Responder,
        HandshakeConfig {
            local_static: Some(KeyPair::generate(DhKind::X25519).unwrap()),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap();
    (init, resp)
}

#[test]
fn initiator_cannot_write_a_responder_message() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    // Now it is the responder's turn; the initiator must refuse to write.
    match init.write_message(b"") {
        Err(NoiseError::WrongRole { expected }) => assert_eq!(expected, "responder"),
        other => panic!("expected WrongRole, got {other:?}"),
    }
}

#[test]
fn responder_cannot_read_out_of_order() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let _m1 = resp.write_message(b"").unwrap();

    // The initiator is expected to *read* message 1. Feeding a *stale*
    // message 0 after progress has been made must fail: the pattern requires
    // more bytes than the stale message contains, and even a longer stale
    // message would fail authentication against the advanced transcript.
    let err = init.read_message(&m0.bytes).unwrap_err();
    assert!(
        matches!(
            err,
            NoiseError::MessageTooShort { .. } | NoiseError::DecryptionFailed(_)
        ),
        "out-of-order message must be rejected, got {err:?}"
    );
}

#[test]
fn replay_of_an_earlier_message_fails() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1.bytes).unwrap();

    // Replaying m0 into a state that expects message 2 must not verify: the
    // AEAD already mixes in the whole transcript, and the stale message is
    // also too short for message 2's token structure.
    let err = resp.read_message(&m0.bytes).unwrap_err();
    assert!(
        matches!(
            err,
            NoiseError::MessageTooShort { .. } | NoiseError::DecryptionFailed(_)
        ),
        "replay must be rejected, got {err:?}"
    );
}

#[test]
fn a_failed_read_poisons_the_handshake() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let m1 = resp.write_message(b"").unwrap();

    let mut bad = m1.bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    assert!(init.read_message(&bad).is_err());

    // Tokens may already have been mixed before the tag check failed, so the
    // state is unusable -- it must not accept the genuine message either.
    match init.read_message(&m1.bytes) {
        Err(NoiseError::InvalidState(_)) => {}
        other => panic!("a poisoned state must refuse all further messages, got {other:?}"),
    }
    match init.write_message(b"") {
        Err(NoiseError::InvalidState(_)) => {}
        other => panic!("a poisoned state must refuse writes too, got {other:?}"),
    }
}

#[test]
fn truncated_messages_are_rejected() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    for cut in [0usize, 1, 16, 31] {
        let short = &m0.bytes[..cut];
        assert!(
            resp.read_message(short).is_err(),
            "cut {cut} must be rejected"
        );
    }
}

#[test]
fn a_token_failure_also_poisons_the_handshake() {
    // Craft a message that is long enough for the fixed-size tokens but whose
    // encrypted static key is corrupt. `s` has already mixed `e` into `h`
    // before failing, so the state must refuse to continue.
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();

    let m1 = resp.write_message(b"").unwrap();
    // Message 1 is e (32) || Enc(s) (48) || payload ciphertext. Flip a byte in
    // the encrypted static key, which the initiator parses *after* mixing `e`
    // and `ee` into its state.
    let mut bad = m1.bytes.clone();
    bad[40] ^= 0xff;
    assert!(init.read_message(&bad).is_err());
    // The state must be poisoned: the real message must not be accepted now.
    assert!(matches!(
        init.read_message(&m1.bytes),
        Err(NoiseError::InvalidState(_))
    ));
}

#[test]
fn oversized_messages_are_rejected() {
    let (mut init, mut resp) = xx_pair();
    let payload = vec![0u8; MAX_MESSAGE_LEN];
    match init.write_message(&payload) {
        Err(NoiseError::MessageTooLong { max, .. }) => assert_eq!(max, MAX_MESSAGE_LEN),
        other => panic!("expected MessageTooLong, got {other:?}"),
    }
    let _ = &mut resp;
}

#[test]
fn unauthenticated_prefix_of_xx_message_0_is_caught_at_message_1() {
    // In XX, message 0 carries only the ephemeral public key and a payload,
    // with no key established yet -- so it cannot be authenticated (this is a
    // documented property of the pattern, not a defect). Tampering with it
    // must therefore surface as a failure on the *next* message, which is
    // authenticated and bound to the whole transcript.
    let (mut init, mut resp) = xx_pair();
    let mut m0 = init.write_message(b"hello").unwrap();
    // Flip a byte in the ephemeral public key. Most 32-byte strings decode to
    // a valid point, so this is accepted here...
    m0.bytes[0] ^= 0x01;
    let accepted = resp.read_message(&m0.bytes).is_ok();
    // ...but the transcript is now divergent, so message 1 cannot verify.
    let m1 = resp.write_message(b"").unwrap();
    assert!(accepted, "XX message 0 is intentionally unauthenticated");
    assert!(
        init.read_message(&m1.bytes).is_err(),
        "a tampered transcript must fail on the first authenticated message"
    );
}

#[test]
fn public_key_validation_rejects_bad_keys() {
    assert!(matches!(
        PublicKey::from_bytes(DhKind::X25519, &[0u8; 31]),
        Err(NoiseError::InvalidKeyLength {
            expected: 32,
            got: 31
        })
    ));
    // The all-zero point would yield a non-contributory shared secret.
    assert!(matches!(
        PublicKey::from_bytes(DhKind::X25519, &[0u8; 32]),
        Err(NoiseError::InvalidPublicKey(_))
    ));
    // A mismatched DH kind is refused when configuring the handshake.
    let p = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let x448_key = KeyPair::generate(DhKind::X448).unwrap();
    let err = HandshakeState::new(
        p,
        Role::Initiator,
        HandshakeConfig {
            local_static: Some(x448_key),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap_err();
    assert!(matches!(err, NoiseError::InvalidState(_)), "got {err:?}");
}

#[test]
fn handshake_cannot_be_used_after_completion() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0.bytes).unwrap();
    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1.bytes).unwrap();
    let m2 = init.write_message(b"").unwrap();
    resp.read_message(&m2.bytes).unwrap();
    assert!(init.is_complete() && resp.is_complete());

    match init.write_message(b"") {
        Err(NoiseError::HandshakeComplete) => {}
        other => panic!("expected HandshakeComplete, got {other:?}"),
    }
    match resp.read_message(&m2.bytes) {
        Err(NoiseError::HandshakeComplete) => {}
        other => panic!("expected HandshakeComplete, got {other:?}"),
    }
}

#[test]
fn empty_payload_messages_are_valid() {
    let (mut init, mut resp) = xx_pair();
    let m0 = init.write_message(b"").unwrap();
    let r0 = resp.read_message(&m0.bytes).unwrap();
    assert!(r0.payload.is_empty());
    assert_eq!(r0.index, 0);
    assert_eq!(r0.sender, Role::Initiator);
}

#[test]
fn psk_required_is_enforced() {
    let p = ProtocolParams::from_parts("NNpsk0", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let err = HandshakeState::new(
        p,
        Role::Initiator,
        HandshakeConfig::default(),
        TraceMode::Off,
    )
    .unwrap_err();
    assert!(matches!(err, NoiseError::PskRequired));
}

#[test]
fn psk_not_allowed_is_enforced() {
    let p = ProtocolParams::from_parts("XX", "25519", "ChaChaPoly", "BLAKE2s").unwrap();
    let err = HandshakeState::new(
        p,
        Role::Initiator,
        HandshakeConfig {
            psk: Some([0u8; 32]),
            ..Default::default()
        },
        TraceMode::Off,
    )
    .unwrap_err();
    assert!(matches!(err, NoiseError::PskNotAllowed));
}
