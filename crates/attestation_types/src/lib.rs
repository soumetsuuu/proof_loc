use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid attestation object format: {0}")]
    InvalidAttestationObject(String),
}

/// Attestation payload shared between the mock client and verifier.
/// lat/lon use scaled integer degrees (e.g., degrees * 1e7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub lat: i64,
    pub lon: i64,
    pub timestamp: i64,
    pub nonce_b64: String,
    pub key_id: String,
    pub assertion_b64: String,
    /// Optional JSON string that, in the mock flow, contains the P-256 public key
    /// used to verify the assertion. Real iOS would carry an Apple-signed
    /// attestation object binding the key to the app.
    pub attestation_object: Option<String>,
}

impl Attestation {
    pub fn nonce_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        Ok(STANDARD.decode(&self.nonce_b64)?)
    }
    pub fn assertion_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        Ok(STANDARD.decode(&self.assertion_b64)?)
    }
}

/// Helper to create the canonical message bytes to sign/verify.
/// Format: big-endian i64(lat) || i64(lon) || i64(timestamp) || nonce
pub fn message_to_sign(lat: i64, lon: i64, timestamp: i64, nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 8 + 8 + nonce.len());
    msg.extend_from_slice(&lat.to_be_bytes());
    msg.extend_from_slice(&lon.to_be_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(nonce);
    msg
}

/// Mock attestation object schema used to carry a raw P-256 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockAttestationObject {
    pub alg: String,      // e.g., "ES256"
    pub pubkey_b64: String, // compressed SEC1 encoded public key
}

impl MockAttestationObject {
    pub fn from_json_str(s: &str) -> Result<Self, AttestationError> {
        serde_json::from_str::<Self>(s).map_err(|e| {
            AttestationError::InvalidAttestationObject(format!("{e}"))
        })
    }
}
