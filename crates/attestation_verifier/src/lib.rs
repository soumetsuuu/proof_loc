use attestation_types::{message_to_sign, Attestation, AttestationError, MockAttestationObject};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ecdsa::{signature::Verifier as _, Signature};
use geo::{algorithm::contains::Contains, prelude::HaversineDistance, Point, Polygon};
use p256::{ecdsa::VerifyingKey, elliptic_curve::sec1::FromEncodedPoint, PublicKey as P256PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    #[error("missing attestation_object public key")]
    MissingPublicKey,
    #[error("invalid public key encoding: {0}")]
    InvalidPubKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub timestamp: i64,
    pub key_id: String,
}

/// Verify signature and return parsed attestation with degrees.
pub fn verify_attestation(att: &Attestation, scale: i64) -> Result<VerifiedAttestation, VerifyError> {
    let nonce = att.nonce_bytes()?;
    let msg = message_to_sign(att.lat, att.lon, att.timestamp, &nonce);
    let digest = Sha256::digest(&msg);

    // Extract public key from mock attestation object
    let mock = att
        .attestation_object
        .as_ref()
        .ok_or(VerifyError::MissingPublicKey)
        .and_then(|s| Ok(MockAttestationObject::from_json_str(s)?))?;
    let pubkey_bytes = STANDARD
        .decode(mock.pubkey_b64)
        .map_err(|e| VerifyError::InvalidPubKey(e.to_string()))?;
    let enc = p256::EncodedPoint::from_bytes(&pubkey_bytes)
        .map_err(|e| VerifyError::InvalidPubKey(e.to_string()))?;
    let pubkey: Option<P256PublicKey> = P256PublicKey::from_encoded_point(&enc).into();
    let pubkey = pubkey.ok_or_else(|| VerifyError::InvalidPubKey("point not on curve".into()))?;
    let verify_key = VerifyingKey::from(pubkey);

    // Decode signature (fixed-size 64-byte, r||s as per ecdsa crate)
    let sig_bytes = att.assertion_bytes()?;
    let sig = Signature::<p256::NistP256>::from_slice(&sig_bytes)
        .map_err(|e| VerifyError::InvalidSignature(e.to_string()))?;
    verify_key
        .verify(&digest, &sig)
        .map_err(|e| VerifyError::InvalidSignature(e.to_string()))?;

    Ok(VerifiedAttestation {
        lat_deg: att.lat as f64 / scale as f64,
        lon_deg: att.lon as f64 / scale as f64,
        timestamp: att.timestamp,
        key_id: att.key_id.clone(),
    })
}

pub fn bbox_contains(lat_deg: f64, lon_deg: f64, min_lat: f64, min_lon: f64, max_lat: f64, max_lon: f64) -> bool {
    lat_deg >= min_lat && lat_deg <= max_lat && lon_deg >= min_lon && lon_deg <= max_lon
}

pub fn circle_contains(lat_deg: f64, lon_deg: f64, center_lat: f64, center_lon: f64, radius_m: f64) -> bool {
    let p = Point::new(lon_deg, lat_deg);
    let c = Point::new(center_lon, center_lat);
    let dist_m = p.haversine_distance(&c);
    dist_m <= radius_m
}

pub fn polygon_contains(lat_deg: f64, lon_deg: f64, polygon_coords: &[(f64, f64)]) -> bool {
    // polygon_coords are (lat, lon); geo expects (x=lon, y=lat)
    let exterior: Vec<geo_types::Coord> = polygon_coords
        .iter()
        .map(|(lat, lon)| geo_types::coord! { x: *lon, y: *lat })
        .collect();
    let poly = Polygon::new(exterior.into(), vec![]);
    let p = Point::new(lon_deg, lat_deg);
    poly.contains(&p)
}
