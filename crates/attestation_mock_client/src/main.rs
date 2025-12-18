use std::{fs, path::PathBuf};

use attestation_types::{message_to_sign, Attestation, MockAttestationObject};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use ecdsa::signature::Signer;
use p256::{ecdsa::{Signature, SigningKey}, elliptic_curve::sec1::ToEncodedPoint, PublicKey as P256PublicKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Debug, Parser)]
#[command(name = "attestation-mock")] 
#[command(about = "Generate mock iOS-like location attestations (P-256 ECDSA)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate a new attestation JSON file
    Gen {
        /// Latitude in decimal degrees (e.g., 37.7749)
        #[arg(long)]
        lat_deg: f64,
        /// Longitude in decimal degrees (e.g., -122.4194)
        #[arg(long)]
        lon_deg: f64,
        /// Timestamp (Unix seconds). Default: now
        #[arg(long)]
        timestamp: Option<i64>,
        /// Nonce length in bytes (random). Default: 32
        #[arg(long, default_value_t = 32)]
        nonce_len: usize,
        /// Scale factor for degrees to i64. Default: 1e7
        #[arg(long, default_value_t = 10_000_000i64)]
        scale: i64,
        /// Output file path. If omitted, prints to stdout
        #[arg(long)]
        out: Option<PathBuf>,
        /// Write the generated public key (compressed) to this file (base64)
        #[arg(long)]
        pubkey_out: Option<PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Gen { lat_deg, lon_deg, timestamp, nonce_len, scale, out, pubkey_out } => {
            let now = timestamp.unwrap_or_else(|| {
                // Seconds since epoch
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            });

            // Convert degrees to scaled i64
            let lat = (lat_deg * scale as f64).round() as i64;
            let lon = (lon_deg * scale as f64).round() as i64;

            // Generate random nonce
            let mut nonce = vec![0u8; nonce_len];
            getrandom::getrandom(&mut nonce)?;

            // Generate an ephemeral P-256 key (mock Secure Enclave/App Attest key)
            let signing_key = SigningKey::random(&mut OsRng);
            let verify_key: P256PublicKey = signing_key.verifying_key().into();
            let pubkey_bytes = verify_key.to_encoded_point(true).as_bytes().to_vec(); // compressed SEC1

            // key_id: base64 of compressed pubkey
            let key_id = STANDARD.encode(&pubkey_bytes);

            // Build message and sign (sha256 over message)
            let msg = message_to_sign(lat, lon, now, &nonce);
            let digest = Sha256::digest(&msg);
            let signature: Signature = signing_key.sign(&digest);
            let signature_bytes = signature.to_bytes();

            // Mock attestation object carries the raw public key for verifier
            let mock_obj = MockAttestationObject {
                alg: "ES256".to_string(),
                pubkey_b64: STANDARD.encode(&pubkey_bytes),
            };
            let attestation_object = Some(serde_json::to_string(&mock_obj)?);

            let att = Attestation {
                lat,
                lon,
                timestamp: now,
                nonce_b64: STANDARD.encode(&nonce),
                key_id,
                assertion_b64: STANDARD.encode(&signature_bytes),
                attestation_object,
            };

            // Optional: write pubkey out separately
            if let Some(pk_path) = pubkey_out {
                fs::write(pk_path, STANDARD.encode(&pubkey_bytes))?;
            }

            let json = serde_json::to_string_pretty(&att)?;
            if let Some(out_path) = out {
                fs::write(out_path, json)?;
            } else {
                println!("{}", json);
            }
        }
    }
    Ok(())
}
