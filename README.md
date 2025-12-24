# Location Proof with SP1 zkVM

Zero knowledge proof system for iOSstyle location attestations (in this project: represented as a P256 ECDSA singature) using [SP1](https://github.com/succinctlabs/sp1). Proves that a cryptographically signed location satisfies a constraint (bounding box, circle, or polygon) without revealing the exact coordinates.

- **PrivacyPreserving**: Exact coordinates never leave the zkVM; only constraint satisfaction is proven
- **Cryptographic Verification**: P256 ECDSA signature verification inside the zkVM (without precompile optimizations)
- **Constraint Types**: Bounding box, circular radius, or arbitrary polygon regions
- Constraint parameters are hashed (SHA256) and committed in the proof

## Quick Start

### Prerequisites

- Rust (with `cargo`)
- SP1 toolchain installed ([instructions](https://docs.succinct.xyz/getting-started/install.html))

### 1. Generate a Mock Location Attestation

Create a signed attestation for New York City coordinates:

```bash
cd crates/attestation_mock_client
cargo run -- gen --lat-deg 40.7128 --lon-deg=-74.0060 --out ../../att_nyc.json
```

This produces an attestation JSON file with:
- Scaled coordinates (lat/lon as `i64` with `1e7` scaling factor)
- Random nonce
- P256 ECDSA signature
- Public key embedded in the attestation object

### 2. Execute Proof with a Bounding Box Constraint

Run the SP1 program in execute mode (fast, no proof generation) to verify a bounding box constraint:

```bash
cd crates/location_proof/
cargo run --release -- \
  --execute \
  --attestation-path ../../att_nyc.json \
  --constraint-type 0 \
  --bbox-min-lat 406000000 \
  --bbox-min-lon=-741500000 \
  --bbox-max-lat 408000000 \
  --bbox-max-lon=-739000000
```

**Output:**
```
Program executed successfully.
Constraint satisfied: true
Constraint type: 0
Timestamp: 1765864876
Constraint (raw): bbox:406000000,-741500000,408000000,-739000000
Local hash (sha256): 36024381730ed32139f6e73ecb8193d6dcc5b3a949949503b6c3d3efd477d834
Public hash: 36024381730ed32139f6e73ecb8193d6dcc5b3a949949503b6c3d3efd477d834
Hash match: true
Total cycles: 12379555
```

### 3. Try Other Constraint Types

**Circle constraint** (10km radius around a point):
```bash
cargo run --release -- \
  --execute \
  --attestation-path ../../att_nyc.json \
  --constraint-type 1 \
  --circle-lat 407128000 \
  --circle-lon=-740060000 \
  --circle-radius-m 10000
```

**Polygon constraint**:
```bash
cargo run --release -- \
  --execute \
  --attestation-path ../../att_nyc.json \
  --constraint-type 2 \
  --polygon-coords "406000000,-742000000,408000000,-742000000,408000000,-738000000,406000000,-738000000"
```

### 4. Submit to Succinct Prover Network

Folow the intructions to deposit PROVE into your requester account: https://docs.succinct.xyz/docs/sp1/prover-network/quickstart then run

```bash 
cargo run --bin network --release -- --attestation-path ../../att_nyc.json   --constraint-type 0   --bbox-min-lat 406000000   --bbox-min-lon=-741500000   --bbox-max-lat 408000000   --bbox-max-lon=-739000000
```

## Crates Structure

- **`crates/attestation_mock_client`**: Generate mock signed attestations
- **`crates/attestation_types`**: Shared types for attestations
- **`crates/attestation_verifier`**: P256 signature verification and geometry checks
- **`crates/location_proof/`**: 
  - `program/`: Contains program whose execution is being proved
  - `script/`: Scripts for local execution / submitting to succinct network

## General Ideas

1. **Attestation Generation**: Mock client generates a P256 signed attestation with lat/lon/timestamp
2. **zkVM Execution**: SP1 program verifies the signature and checks constraint satisfaction
3. **Public Output**: Only the constraint hash, satisfaction result, and timestamp are revealed
4. **Privacy**: Exact coordinates only revealed to prover

## Coordinate Scaling

All coordinates use a fixed scaling factor of `1e7`:
- `37.7749°` → `377749000`
- `-122.4194°` → `-1224194000`

This allows integer arithmetic while preserving ~1cm precision.