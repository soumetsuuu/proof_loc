//Executes attestation verification or generate proofs

use alloy_sol_types::SolType;
use attestation_types::Attestation;
use clap::Parser;
use location_proof_lib::{constraint_hash_bytes32, constraint_string, AttestationInput, PublicValuesStruct};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::fs;

/// The ELF file for the Succinct RISC-V zkVM
pub const LOCATION_PROOF_ELF: &[u8] = include_elf!("location-proof-program");

/// The arguments for the command
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    // Attestation data
    #[arg(long, default_value = "377749000")] // SF lat in scaled units
    lat: i64,

    #[arg(long, default_value = "-122419400")] // SF lon in scaled units
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

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::from_env();

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

    println!("Input: constraint_type={}, timestamp={}", input.constraint_type, input.timestamp);
    println!("Lat: {}, Lon: {}", input.lat, input.lon);
    println!("Attestation key_id: {}", input.key_id);

    if args.execute {
        println!("\n=== EXECUTE MODE ===");
        let (output, report) = client.execute(LOCATION_PROOF_ELF, &stdin).run().unwrap();
        println!("Program executed successfully.");

        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        println!("Constraint satisfied: {}", decoded.constraint_satisfied);
        println!("Constraint type: {}", decoded.constraint_type);
        println!("Timestamp: {}", decoded.timestamp);
        // Print raw constraint and verify public hash
        let constraint_str = constraint_string(&input);
        let local_hash = constraint_hash_bytes32(&input);
        let public_hash = decoded.constraint_data.as_slice();
        println!("Constraint (raw): {}", constraint_str);
        println!("Local hash (sha256): {}", hex::encode(local_hash));
        println!("Public hash: {}", hex::encode(public_hash));
        println!("Hash match: {}", local_hash == public_hash);
        println!("Total cycles: {}", report.total_instruction_count());
    } else {
        println!("\n=== PROVE MODE ===");
        let (pk, vk) = client.setup(LOCATION_PROOF_ELF);
        println!("Setup complete. Generating proof...");

        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");

        // Verify proof locally
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof locally!");

        // Display proof info
        let decoded = PublicValuesStruct::abi_decode(proof.public_values.as_slice()).unwrap();
        println!("\n=== PROOF RESULTS ===");
        println!("Constraint satisfied: {}", decoded.constraint_satisfied);
        println!("Constraint type: {}", decoded.constraint_type);
        println!("Timestamp: {}", decoded.timestamp);
        // Print raw constraint and verify public hash
        let constraint_str = constraint_string(&input);
        let local_hash = constraint_hash_bytes32(&input);
        let public_hash = decoded.constraint_data.as_slice();
        println!("Constraint (raw): {}", constraint_str);
        println!("Local hash (sha256): {}", hex::encode(local_hash));
        println!("Public hash: {}", hex::encode(public_hash));
        println!("Hash match: {}", local_hash == public_hash);
    }
}
