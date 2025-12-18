use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use attestation_types::Attestation;
use attestation_verifier::{verify_attestation, circle_contains, polygon_contains};

sol! {
    struct PublicValuesStruct {
        bool constraint_satisfied;
        uint8 constraint_type;
        bytes32 constraint_data; // packed constraint parameters
        int64 timestamp;
    }
}

/// Input: full attestation with signature for cryptographic verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInput {
    // scaled i64
    pub lat: i64,
    pub lon: i64,
    pub timestamp: i64,
    pub nonce_b64: String,
    pub key_id: String,
    pub assertion_b64: String, // 64 byte P256 signature (r||s)
    pub attestation_object: String, // JSON with alg and pubkey_b64
    
    pub constraint_type: u8, // 0=bbox, 1=circle, 2=polygon
    
    // Bbox parameters 
    pub bbox_min_lat: i64,
    pub bbox_min_lon: i64,
    pub bbox_max_lat: i64,
    pub bbox_max_lon: i64,
    
    // Circle parameters
    pub circle_lat: i64,
    pub circle_lon: i64,
    pub circle_radius_m: i32,
    
    // Polygon parameters
    // polygon_coords flattened: [lat0, lon0, lat1, lon1, ...]
    pub polygon_coords: Vec<i64>,
}

pub const SCALE: i64 = 10_000_000; // degrees * 1e7 = scaled i64

/// Verify P256 ECDSA signature (running inside SP1)
pub fn verify_signature(
    lat: i64,
    lon: i64,
    timestamp: i64,
    nonce_b64: &str,
    assertion_b64: &str,
    attestation_object_json: &str,
) -> bool {
    let att = Attestation {
        lat,
        lon,
        timestamp,
        nonce_b64: nonce_b64.to_string(),
        key_id: String::new(),
        assertion_b64: assertion_b64.to_string(),
        attestation_object: Some(attestation_object_json.to_string()),
    };
    verify_attestation(&att, SCALE).is_ok()
}

/// Check if coordinates satisfy bounding box constraint
pub fn verify_bbox(
    lat: i64,
    lon: i64,
    min_lat: i64,
    min_lon: i64,
    max_lat: i64,
    max_lon: i64,
) -> bool {
    lat >= min_lat && lat <= max_lat && lon >= min_lon && lon <= max_lon
}

/// Check if coordinates satisfy circle constraint using Haversine distance.
/// radius_m: radius in meters (converted to degrees: degrees = meters / 111_000)
pub fn verify_circle(lat: i64, lon: i64, center_lat: i64, center_lon: i64, radius_m: i32) -> bool {
    let lat_deg = lat as f64 / SCALE as f64;
    let lon_deg = lon as f64 / SCALE as f64;
    let center_lat_deg = center_lat as f64 / SCALE as f64;
    let center_lon_deg = center_lon as f64 / SCALE as f64;
    circle_contains(lat_deg, lon_deg, center_lat_deg, center_lon_deg, radius_m as f64)
}

/// Check if coordinates satisfy polygon constraint.
/// polygon_coords is a flattened array: [lat0, lon0, lat1, lon1, ...]
/// Uses ray casting algorithm for point-in-polygon test.
pub fn verify_polygon(lat: i64, lon: i64, polygon_coords: &[i64]) -> bool {
    if polygon_coords.len() < 6 {
        return false; // Need at least 3 points (6 coordinates)
    }
    let lat_deg = lat as f64 / SCALE as f64;
    let lon_deg = lon as f64 / SCALE as f64;
    // polygon_coords are lat,lon pairs; convert to (lat, lon) f64 vec
    let mut pts = Vec::with_capacity(polygon_coords.len() / 2);
    for pair in polygon_coords.chunks_exact(2) {
        pts.push((pair[0] as f64 / SCALE as f64, pair[1] as f64 / SCALE as f64));
    }
    polygon_contains(lat_deg, lon_deg, &pts)
}

/// canonical constraint string for hashing/commitment
pub fn constraint_string(input: &AttestationInput) -> String {
    match input.constraint_type {
        0 => format!(
            "bbox:{},{},{},{}",
            input.bbox_min_lat, input.bbox_min_lon, input.bbox_max_lat, input.bbox_max_lon
        ),
        1 => format!(
            "circle:{},{},{}",
            input.circle_lat, input.circle_lon, input.circle_radius_m
        ),
        2 => format!("polygon:{:?}", input.polygon_coords),
        _ => "unknown".to_string(),
    }
}

/// Compute sha256(bytes) and return the first 32 bytes as fixed-size array
pub fn constraint_hash_bytes32(input: &AttestationInput) -> [u8; 32] {
    let s = constraint_string(input);
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}
