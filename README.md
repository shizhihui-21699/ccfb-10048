# noise-rs

A from-scratch implementation of the [Noise Protocol Framework][spec] in Rust,
written to be auditable rather than maximal. It exists to put an authenticated
key exchange in front of internal services without standing up a certificate
authority or a TLS stack.

* **Handshakes**: `XX` (mutual, forward-secret) and `IK` (initiator knows the
  responder's static key) are the supported patterns; all 36 patterns from the
  official test-vector file are also implemented so the state machine can be
  verified against the reference vectors.
* **DH**: X25519 (X448 is available for cross-checking vectors).
* **Ciphers**: ChaCha20-Poly1305 and AES-256-GCM.
* **Hashes**: BLAKE2s and SHA-256 (BLAKE2b / SHA-512 for vector cross-checking).
* **Strict state machine**: wrong-direction, out-of-order and replayed messages
  are rejected; see [Strictness](#strictness).
* **Transport**: sequential or explicit nonces, rekeying, nonce exhaustion
  handling, and a replay window.
* **Tracing**: every handshake step, token, hash and key derivation can be
  printed, with secrets redacted by default.
* **Vectors**: all 576 vectors in the official cacophony file pass byte for
  byte.

```text
$ cargo test
...
test result: ok. 6 passed   (tests/cacophony_vectors.rs)
test result: ok. 10 passed  (tests/cli.rs)
test result: ok. 13 passed  (tests/crypto.rs)
test result: ok. 6 passed   (tests/handshake_xx_ik.rs)
test result: ok. 12 passed  (tests/strictness.rs)
test result: ok. 8 passed   (tests/tracing.rs)
test result: ok. 15 passed  (tests/transport.rs)
```

## Library

```rust
use noise_rs::{HandshakeConfig, HandshakeState, KeyPair, DhKind, ProtocolParams, Role, TraceMode};

let params = ProtocolParams::parse("Noise_XX_25519_ChaChaPoly_BLAKE2s")?;

let mut initiator = HandshakeState::new(
    params.clone(),
    Role::Initiator,
    HandshakeConfig {
        local_static: Some(KeyPair::generate(DhKind::X25519)?),
        prologue: b"service-a<->service-b".to_vec(),
        ..Default::default()
    },
    TraceMode::Redacted,
)?;
let mut responder = HandshakeState::new(
    params,
    Role::Responder,
    HandshakeConfig {
        local_static: Some(KeyPair::generate(DhKind::X25519)?),
        prologue: b"service-a<->service-b".to_vec(),
        ..Default::default()
    },
    TraceMode::Redacted,
)?;

let m0 = initiator.write_message(b"")?;
responder.read_message(&m0.bytes)?;
let m1 = responder.write_message(b"")?;
initiator.read_message(&m1.bytes)?;
let m2 = initiator.write_message(b"")?;
responder.read_message(&m2.bytes)?;

let mut client = initiator.into_transport()?;
let mut server = responder.into_transport()?;
let ct = client.send(b"hello")?;
assert_eq!(server.receive(&ct)?, b"hello");
# Ok::<(), noise_rs::NoiseError>(())
```

The prologue is the right place for application context both sides must agree
on (service names, versions, a config digest). It is mixed into the initial
hash, so a mismatch makes the first authenticated message fail.

## CLI

`noise-cli` runs both parties and prints every step. The wire format is one
line of lowercase hex per frame over TCP, a file pair, or stdin/stdout; a
`#END` line closes a party's outbound transport stream.

```text
# terminal 1
noise-cli serve --listen 127.0.0.1:9000 --pattern XX --message "hi from server"

# terminal 2
noise-cli connect --connect 127.0.0.1:9000 --pattern XX --message "hi from client"
```

The trace looks like this (abridged):

```text
═══ Noise session ═══
  role     : initiator
  protocol : Noise_XX_25519_ChaChaPoly_BLAKE2s
  pattern  :
      -> e
      <- e, ee, s, es
      -> s, se
  [initiator] init protocol=... role=initiator psk=false
        prologue = <empty>
        h  = 2b71c58d...
        ck = 44e9d5d64731d000
▸ initiator: writing handshake message 0 (initiator)
  [initiator] msg #0 token e      (ephemeral public key) (no key yet)
        public_key = db6092fb...
        h  = db6092fb...
  [initiator] msg #0 payload encrypt: 0 -> 0 bytes (n=none, ok=true)
...
  [initiator] SPLIT: handshake complete, transport keys derived
        handshake_hash = 32be949e...
        k1 (init->resp) = 173f66d7a11d660a
        k2 (resp->init) = 59c5d58c7c40c9a2
        sending  = 173f66d7a11d660a
        receiving= 59c5d58c7c40c9a2
─── handshake established ───
  handshake hash (channel binding) = 32be949e...
  authenticated peer static key   = 7f1db532...
```

Keys are shown as 8-byte SHA-256 fingerprints unless `--reveal-secrets` is
passed. Fingerprints let you correlate "same key used here and there" without
logging key material. `--trace-file` appends the same log to a file, and
`--quiet` suppresses it.

### IK provisioning

IK needs the responder's static public key on the initiator ahead of time:

```text
# Print the responder's key pair (use --static-key to keep a fixed one).
noise-cli serve --pattern IK --print-static-key
# secret <hex>
# public <hex>

# Responder, with the secret configured
noise-cli serve --pattern IK --static-key <secret>

# Initiator, pinning the public key
noise-cli connect --pattern IK --remote-static <public>
```

If the initiator is configured with the wrong key, the handshake fails
immediately (the responder's static key is encrypted under a key derived from
`es`, so decryption of message 0 fails). If a remote static key is supplied
for a pattern that transmits the peer's key (`XX`), the CLI compares the
authenticated key with the pinned value and refuses the session on mismatch.

### Options

```text
--pattern   XX | IK
--cipher    ChaChaPoly | AESGCM
--hash      BLAKE2s | SHA256
--dh        25519 | 448
--prologue  string mixed into the initial hash
--static-key <hex>        provision a fixed static secret
--print-static-key        print the key pair and exit
--reveal-secrets          show raw keys instead of fingerprints
--trace-file <path>       append the trace to a file
--quiet                   no trace
--wire      tcp | file | stdio
--message/-m <payload>    transport message to send (repeatable)
--interactive             read transport messages from stdin
--rekey-every <n>         rekey send/receive keys every n messages
--no-receive              do not read the peer's transport messages
--connect-timeout-ms <n>  retry the initial connection until the server is up
```

## Strictness

The state machine rejects rather than repairs:

| Situation | Result |
| --- | --- |
| Writing a message that belongs to the peer | `WrongRole` |
| Reading a message the peer did not send | `WrongRole` |
| A message shorter than its tokens require | `MessageTooShort` |
| A message longer than 65535 bytes | `MessageTooLong` |
| AEAD tag mismatch / modified ciphertext | `DecryptionFailed` |
| An `s` token after the remote static key is already known | `UnexpectedStaticKey` |
| A required key was not supplied | `MissingKey` |
| `psk` token without a PSK | `PskRequired` |
| PSK supplied to a non-PSK pattern | `PskNotAllowed` |
| A message after the handshake completed | `HandshakeComplete` |
| Nonce about to reach `2^64-1` | `NonceExhausted` |
| Explicit nonce already accepted (or outside the window) | `ReplayDetected` |

**Replay and reordering.** The pattern fixes which message may come next, the
AEAD associated data chains every prior message into `h`, and the message
counter advances monotonically. A handshake message that is out of order,
replayed, or from a different transcript therefore fails authentication instead
of being reinterpreted as a different step.

**Poisoning.** A rejected message may already have mixed tokens into `h` and
`ck` before the failure was detected, so continuing from it would run the rest
of the pattern on corrupted state. After any rejection the handshake refuses
every further operation (`InvalidState`); start a new one.

Note that `XX` message 0 carries only an ephemeral key and a payload with no
key established yet, so it is not authenticated — that is a property of the
pattern. Tampering with it surfaces on message 1, which is authenticated and
binds the whole transcript.

**Transport replay.** With sequential nonces, both parties advance together,
so a replayed ciphertext is decrypted under the wrong nonce and the tag check
fails. For lossy or reordered links, `send_with_nonce`/`receive_with_nonce`
carry the nonce explicitly and reject repeats via a sliding 1024-entry
replay window; a nonce older than the window is refused.

## Rekey and nonce exhaustion

`rekey_sending()` / `rekey_receiving()` implement `REKEY(k) = ENCRYPT(k,
2^64-1, empty, zeros[32])[0..32]`. Rekeying rotates the key **without** resetting
the nonce counter, exactly as section 11.3 describes; both parties must rekey
in lockstep.

Per section 5.1 the maximum nonce `2^64-1` is reserved. A cipher state may use
nonces up to `2^64-2`; using `2^64-2` moves the counter to `2^64-1`, after
which every further `send`/`receive` fails with `NonceExhausted`. Rekeying does
not restore capacity: a session that has consumed its nonce space needs a new
handshake. The CLI's `--rekey-every` exercises rotation, and
`tests/transport.rs` covers exhaustion explicitly.

## Test vectors

`tests/vectors/cacophony.txt` is the public-domain vector file from
[mcginty/cacophony](https://github.com/mcginty/cacophony). Every vector is
replayed with its fixed keys, prologue and payloads; the harness compares every
handshake ciphertext, every decrypted payload, and the reported handshake hash
byte for byte.

One convention is worth knowing: cacophony records `handshake_hash` as the value
its reference implementation holds at its last suspension point — the start of
the final handshake message, or immediately before the final `psk` token — not
the section 11.2 value after `Split()`. The state machine tracks that
checkpoint (`checkpoint_hash`) so comparison is exact, while
`HandshakeState::handshake_hash()` returns the spec value. Both are verified.

The vectors are a real oracle, not decoration: flipping the AESGCM nonce to
little-endian fails 288 of 576, and dropping the PSK-mode `MixKey(e)` rule
fails 336 of 576.

## Layout

| File | Purpose |
| --- | --- |
| `src/crypto.rs` | Hash, HMAC/HKDF, X25519/X448, ChaChaPoly/AESGCM, REKEY |
| `src/symmetric.rs` | `CipherState` / `SymmetricState`, nonce handling |
| `src/patterns.rs` | Pattern definitions and the token model |
| `src/params.rs` | Protocol-name parsing and validation |
| `src/handshake.rs` | The strict handshake state machine |
| `src/transport.rs` | Transport messages, rekey, replay window |
| `src/trace.rs` | Structured trace events and secret redaction |
| `src/trace_sink.rs` | Human-readable rendering for the CLI |
| `src/vectors.rs` | Vector loader and runner |
| `src/bin/noise-cli.rs` | Two-party command-line driver |

## Scope and caveats

* This is an independent implementation, not a formally audited one. It has
  not had third-party review; treat it accordingly before protecting
  production traffic.
* The crate performs no record framing, length limits beyond the 65535-byte
  Noise limit, or session management; that is the application's job.
* `IK` requires the responder's static key to be distributed out of band. `XX`
  needs no provisioning but both parties must be able to accept an unknown
  peer key (the CLI prints the authenticated key after the handshake so
  higher layers can pin it).
* Key material is zeroized on drop for `CipherState`, `SymmetricState` and
  `KeyPair`, and `Debug` never prints secrets. `--reveal-secrets` exists for
  local debugging only.

[spec]: https://noiseprotocol.org/noise.html
