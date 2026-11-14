//! Protocol-name parsing and the negotiated parameter set.

use crate::crypto::{CipherKind, DhKind, HashKind};
use crate::error::NoiseError;
use crate::patterns::{self, Pattern};

/// The four protocol-name sections of a Noise protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolParams {
    /// The handshake pattern.
    pub pattern: Pattern,
    /// The DH function.
    pub dh: DhKind,
    /// The AEAD cipher.
    pub cipher: CipherKind,
    /// The hash function.
    pub hash: HashKind,
}

impl ProtocolParams {
    /// Builds the canonical protocol name, e.g.
    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
    pub fn protocol_name(&self) -> Vec<u8> {
        format!(
            "Noise_{}_{}_{}_{}",
            self.pattern.name,
            self.dh.name(),
            self.cipher.name(),
            self.hash.name()
        )
        .into_bytes()
    }

    /// Parses a protocol name.
    ///
    /// The name must have exactly the form
    /// `Noise_<pattern>_<dh>_<cipher>_<hash>`. Pattern names may contain the
    /// lowercase PSK modifier suffix (e.g. `XXpsk3`); no other modifiers are
    /// supported, and any `+`-separated compound sections are rejected.
    pub fn parse(protocol_name: &str) -> Result<Self, NoiseError> {
        let rest = protocol_name
            .strip_prefix("Noise_")
            .ok_or_else(|| NoiseError::InvalidProtocolName(protocol_name.to_owned()))?;
        let parts: Vec<&str> = rest.split('_').collect();
        if parts.len() != 4 {
            return Err(NoiseError::InvalidProtocolName(protocol_name.to_owned()));
        }
        if protocol_name.len() > 255 {
            return Err(NoiseError::InvalidProtocolName(
                "protocol names must be at most 255 bytes".to_owned(),
            ));
        }

        let pattern = patterns::lookup(parts[0]).ok_or_else(|| {
            NoiseError::UnsupportedAlgorithm(format!("handshake pattern {}", parts[0]))
        })?;
        let dh = DhKind::from_name(parts[1])
            .ok_or_else(|| NoiseError::UnsupportedAlgorithm(format!("DH function {}", parts[1])))?;
        let cipher = CipherKind::from_name(parts[2])
            .ok_or_else(|| NoiseError::UnsupportedAlgorithm(format!("cipher {}", parts[2])))?;
        let hash = HashKind::from_name(parts[3]).ok_or_else(|| {
            NoiseError::UnsupportedAlgorithm(format!("hash function {}", parts[3]))
        })?;

        Ok(ProtocolParams {
            pattern,
            dh,
            cipher,
            hash,
        })
    }

    /// Parses a name or constructs one from its components.
    pub fn from_parts(
        pattern: &str,
        dh: &str,
        cipher: &str,
        hash: &str,
    ) -> Result<Self, NoiseError> {
        Self::parse(&format!("Noise_{pattern}_{dh}_{cipher}_{hash}"))
    }
}
