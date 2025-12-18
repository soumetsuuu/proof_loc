// This program runs inside the SP1 zkVM and produces a proof of constraint satisfaction without revealing the exact coordinates.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use location_proof_lib::{
    verify_bbox, verify_circle, verify_polygon, verify_signature, AttestationInput, PublicValuesStruct,
    constraint_hash_bytes32, constraint_string,
};

pub fn main() {
    // Read attestation + constraint input
    let input = sp1_zkvm::io::read::<AttestationInput>();

    let signature_valid = verify_signature(
        input.lat,
        input.lon,
        input.timestamp,
        &input.nonce_b64,
        &input.assertion_b64,
        &input.attestation_object,
    );

    if !signature_valid {
        let output = PublicValuesStruct {
            constraint_satisfied: false,
            constraint_type: input.constraint_type,
            constraint_data: [0u8; 32].into(),
            timestamp: input.timestamp,
        };
        let bytes = PublicValuesStruct::abi_encode(&output);
        sp1_zkvm::io::commit_slice(&bytes);
        return;
    }

    let constraint_satisfied = match input.constraint_type {
        0 => {
            // Bounding box
            verify_bbox(
                input.lat,
                input.lon,
                input.bbox_min_lat,
                input.bbox_min_lon,
                input.bbox_max_lat,
                input.bbox_max_lon,
            )
        }
        1 => {
            // Circle with Haversine distance
            verify_circle(
                input.lat,
                input.lon,
                input.circle_lat,
                input.circle_lon,
                input.circle_radius_m,
            )
        }
        2 => {
            // Polygon containment
            verify_polygon(input.lat, input.lon, &input.polygon_coords)
        }
        _ => false,
    };

    //Commit public output with hashed constraint data
    let _constraint_str = constraint_string(&input);
    let constraint_data = constraint_hash_bytes32(&input);

    let output = PublicValuesStruct {
        constraint_satisfied,
        constraint_type: input.constraint_type,
        constraint_data: constraint_data.into(),
        timestamp: input.timestamp,
    };

    let bytes = PublicValuesStruct::abi_encode(&output);
    sp1_zkvm::io::commit_slice(&bytes);
}
