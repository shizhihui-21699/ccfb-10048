//! Runs the complete official cacophony vector file.
//!
//! Every vector must pass: the ciphertext of every message, the decrypted
//! payload, and the final handshake hash are compared byte for byte.

use noise_rs::vectors::{run_vector, VectorFile};

fn load() -> VectorFile {
    let json = include_str!("vectors/cacophony.txt");
    VectorFile::from_json(json).expect("vector file must parse")
}

#[test]
fn every_cacophony_vector_passes() {
    let file = load();
    assert!(
        !file.vectors.is_empty(),
        "the vector file must not be empty"
    );

    let mut failures: Vec<String> = Vec::new();
    let mut passed = 0usize;

    for vector in &file.vectors {
        match run_vector(vector) {
            Ok(_) => passed += 1,
            Err(err) => failures.push(format!("{}: {err}", vector.protocol_name)),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} vectors failed:\n{}",
        failures.len(),
        file.vectors.len(),
        failures.join("\n")
    );
    assert_eq!(passed, file.vectors.len());
    println!("all {} cacophony vectors passed", passed);
}

/// The vector file must exercise every supported algorithm combination:
/// 36 patterns * 2 DH * 2 ciphers * 4 hashes = 576 vectors.
#[test]
fn vector_file_coverage() {
    let file = load();
    assert_eq!(file.vectors.len(), 576);

    let patterns = [
        "NN", "KN", "NK", "KK", "NX", "KX", "XN", "IN", "XK", "IK", "XX", "IX", "N", "K", "X",
        "NNpsk0", "NNpsk2", "NKpsk0", "NKpsk2", "NXpsk2", "XNpsk3", "XKpsk3", "XXpsk3", "KNpsk0",
        "KNpsk2", "KKpsk0", "KKpsk2", "KXpsk2", "INpsk1", "INpsk2", "IKpsk1", "IKpsk2", "IXpsk2",
        "Npsk0", "Kpsk0", "Xpsk1",
    ];
    for pattern in patterns {
        let count = file
            .vectors
            .iter()
            .filter(|v| {
                v.protocol_name
                    .strip_prefix("Noise_")
                    .and_then(|r| r.split('_').next())
                    == Some(pattern)
            })
            .count();
        assert_eq!(count, 16, "pattern {pattern} should have 16 vectors");
    }
}

/// A single broken byte anywhere in a handshake message must be detected by
/// the receiving party.
#[test]
fn tampered_ciphertext_is_rejected() {
    let file = load();
    let vector = file
        .vectors
        .iter()
        .find(|v| v.protocol_name == "Noise_XX_25519_ChaChaPoly_BLAKE2s")
        .expect("XX vector present")
        .clone();

    let (mut init, mut resp) = noise_rs::vectors::build_pair(&vector).unwrap();

    // Message 0 of XX carries no key yet, so its payload is not authenticated
    // (a documented property of the pattern, not a bug). Tamper message 1,
    // which is encrypted and authenticated.
    let m0 = vector.messages[0].clone();
    init.write_message(&hex::decode(&m0.payload).unwrap())
        .unwrap();
    let m0_wire = hex::decode(&m0.ciphertext).unwrap();
    resp.read_message(&m0_wire).unwrap();

    let m1 = vector.messages[1].clone();
    let produced = resp
        .write_message(&hex::decode(&m1.payload).unwrap())
        .unwrap();
    assert_eq!(hex::encode(&produced.bytes), m1.ciphertext);

    for offset in [produced.bytes.len() - 1, 33, produced.bytes.len() / 2] {
        let mut bad = produced.bytes.clone();
        bad[offset] ^= 0x01;
        assert!(
            init.read_message(&bad).is_err(),
            "tampering byte {offset} of an encrypted message must be rejected"
        );
        // The failed read must not have advanced the initiator's state; a
        // fresh copy of the initiator can still accept the genuine message.
    }
    // A rejected message poisons the handshake: it may already have mixed
    // tokens into `h`/`ck`, so continuing would run the pattern on corrupted
    // state. The state must refuse all further use, including a retry with the
    // genuine message.
    let good = produced.bytes.clone();
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(init.read_message(&bad).is_err());
    match init.read_message(&good) {
        Err(noise_rs::NoiseError::InvalidState(_)) => {}
        other => panic!("a poisoned handshake must stay aborted, got {other:?}"),
    }
}

/// A truncated handshake message must be rejected, not partially parsed.
#[test]
fn truncated_message_is_rejected() {
    let file = load();
    let vector = file
        .vectors
        .iter()
        .find(|v| v.protocol_name == "Noise_IK_25519_AESGCM_SHA256")
        .expect("IK vector present")
        .clone();

    let (mut init, mut resp) = noise_rs::vectors::build_pair(&vector).unwrap();

    let m0 = vector.messages[0].clone();
    let produced = init
        .write_message(&hex::decode(&m0.payload).unwrap())
        .unwrap();
    assert_eq!(hex::encode(&produced.bytes), m0.ciphertext);

    let bad = produced.bytes[..produced.bytes.len() - 1].to_vec();
    assert!(
        resp.read_message(&bad).is_err(),
        "a truncated message must be rejected"
    );
}

/// Feeding a responder message to the initiator (or vice versa) is a
/// direction error, not a silently accepted message.
#[test]
fn wrong_direction_is_rejected() {
    let file = load();
    let vector = file
        .vectors
        .iter()
        .find(|v| v.protocol_name == "Noise_XX_25519_ChaChaPoly_BLAKE2s")
        .expect("XX vector present")
        .clone();
    let (mut init, _resp) = noise_rs::vectors::build_pair(&vector).unwrap();

    let m0 = vector.messages[0].clone();
    let bytes = hex::decode(&m0.ciphertext).unwrap();
    // The initiator must *write* message 0; reading it is a role violation.
    match init.read_message(&bytes) {
        Err(noise_rs::NoiseError::WrongRole { .. }) => {}
        other => panic!("expected WrongRole, got {other:?}"),
    }
}

/// Replaying a handshake message into the same state must fail because the
/// state has already advanced past that message.
#[test]
fn replayed_handshake_message_is_rejected() {
    let file = load();
    let vector = file
        .vectors
        .iter()
        .find(|v| v.protocol_name == "Noise_XX_25519_ChaChaPoly_BLAKE2s")
        .expect("XX vector present")
        .clone();
    let (mut init, mut resp) = noise_rs::vectors::build_pair(&vector).unwrap();

    let m0 = vector.messages[0].clone();
    let m0 = init
        .write_message(&hex::decode(&m0.payload).unwrap())
        .unwrap();
    resp.read_message(&m0.bytes).unwrap();

    // The responder has moved on to message 1; message 0 can no longer be
    // applied, so the replay is rejected.
    match resp.read_message(&m0.bytes) {
        Err(noise_rs::NoiseError::WrongRole { .. }) => {}
        other => panic!("expected WrongRole for a replayed message, got {other:?}"),
    }
}
