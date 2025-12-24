//! Submit proof generation to Succinct Prover Network
//! 
//! Prerequisites:
//! 1. Set up PROVE tokens: https://docs.succinct.xyz/docs/network/developers/key-setup
//! 2. Set environment variables:
//!    - SP1_PRIVATE_KEY=<your_private_key>
//!
//! Run with:
//! ```shell
//! source.env
//! cargo run --release --bin network
//! ```

use alloy_sol_types::SolType;
use clap::Parser;
use location_proof_lib::{AttestationInput, PublicValuesStruct};
use sp1_sdk::{include_elf, ProverClient, Prover, SP1Stdin, network::NetworkMode};
use attestation_types::Attestation;
use std::fs;

pub const LOCATION_PROOF_ELF: &[u8] = include_elf!("location-proof-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {

    #[arg(long, default_value = "377749000")] 
    lat: i64,

    #[arg(long, default_value = "-122419400")] 
    lon: i64,

    #[arg(long, default_value = "1703088000")]
    timestamp: i64,

    #[arg(long, default_value = "test_nonce_b64")]
    nonce_b64: String,

    #[arg(long, default_value = "test_key_id")]
    key_id: String,

    #[arg(long, default_value = "test_sig_b64")]
    assertion_b64: String,

    #[arg(long, default_value = r#"{"alg":"ES256","pubkey_b64":"test_pubkey"}"#)]
    attestation_object: String,

    // Constraint specification
    #[arg(long, default_value = "0")] // 0=bbox, 1=circle, 2=polygon
    constraint_type: u8,

    // Bbox parameters
    #[arg(long, default_value = "376000000")] // bbox min_lat
    bbox_min_lat: i64,

    #[arg(long, default_value = "-123000000")] // bbox min_lon
    bbox_min_lon: i64,

    #[arg(long, default_value = "378000000")] // bbox max_lat
    bbox_max_lat: i64,

    #[arg(long, default_value = "-122000000")] // bbox max_lon
    bbox_max_lon: i64,

    // Circle parameters
    #[arg(long)]
    circle_lat: Option<i64>,

    #[arg(long)]
    circle_lon: Option<i64>,

    #[arg(long, default_value = "5000")]
    circle_radius_m: i32,

    // Polygon coordinates (flattened: lat0,lon0,lat1,lon1,...)
    #[arg(long)]
    polygon_coords: Option<String>,

    /// Path to attestation JSON produced by attestation_mock_client
    #[arg(long)]
    attestation_path: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    let args = Args::parse();
    
    // Parse polygon coordinates if provided
    let polygon_coords = if let Some(coords_str) = args.polygon_coords {
        coords_str
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect::<Vec<i64>>()
    } else {
        vec![]
    };

    // Load attestation from file
    let att_json = fs::read_to_string(&args.attestation_path)
        .expect("failed to read attestation file");
    let att: Attestation = serde_json::from_str(&att_json)
        .expect("failed to parse attestation JSON");

    // Create attestation input with full verification data
    let input = AttestationInput {
        lat: att.lat,
        lon: att.lon,
        timestamp: att.timestamp,
        nonce_b64: att.nonce_b64,
        key_id: att.key_id,
        assertion_b64: att.assertion_b64,
        attestation_object: att.attestation_object.unwrap_or_default(),
        constraint_type: args.constraint_type,
        bbox_min_lat: args.bbox_min_lat,
        bbox_min_lon: args.bbox_min_lon,
        bbox_max_lat: args.bbox_max_lat,
        bbox_max_lon: args.bbox_max_lon,
        circle_lat: args.circle_lat.unwrap_or(args.lat),
        circle_lon: args.circle_lon.unwrap_or(args.lon),
        circle_radius_m: args.circle_radius_m,
        polygon_coords,
    };
    
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    let client = ProverClient::builder()
        .network_for(NetworkMode::Mainnet)
        .build();
    
    println!("Input: constraint_type={}, timestamp={}", input.constraint_type, input.timestamp);
    println!("\n=== SUBMITTING TO PROVER NETWORK ===");
    println!("Estimated cycles: ~14,000-50,000 (depending on constraint)");
    println!("This will consume PROVE tokens based on proof complexity.");

    let (pk, vk) = client.setup(LOCATION_PROOF_ELF);
    println!("\nSubmitting proof request to Succinct Network...");
    let proof = client
        .prove(&pk, &stdin)
        .compressed()
        .run()
        .expect("failed to generate proof on network");

    println!("Proof generated successfully on Succinct Network");

    let decoded = PublicValuesStruct::abi_decode(proof.public_values.as_slice()).unwrap();
    println!("\n=== PROOF RESULTS ===");
    println!("Constraint satisfied: {}", decoded.constraint_satisfied);
    println!("Constraint type: {}", decoded.constraint_type);
    println!("Timestamp: {}", decoded.timestamp);
    
    // Verify locally
    client.verify(&proof, &vk).expect("failed to verify proof");
    println!("Proof verified locally");
}
