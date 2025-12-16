# Privacy Preserving Location Proof System

A Rust based mock iOS attestation system with P256 ECDSA signatures and geometric constraint verification, designed to prove location compliance without revealing exact coordinates to untrusted parties.

## Project Overview

This project implements a phased approach to building a privacy preserving location proof system that can eventually integrate with SP1 zero knowledge proofs:

  **Part 1 (Deferred)**: iOS app generating hardware backed App Attest + Core Location
  **Part 2 (Current)**: Rust attestation verification + coordinate constraint checking
  **Part 3 (Planned)**: SP1 zkVM program for zero knowledge proof generation

**Crates:**

1. **`attestation_types`**: Shared data structures and message formatting
   - `Attestation`: JSON serializable attestation object (lat, lon, timestamp, nonce, signature, public key)
   - `MockAttestationObject`: Mock container for algorithm and raw P 256 public key
   - `message_to_sign()`: Canonical message format for cryptographic signing

2. **`attestation_mock_client`**: Generates mock iOS like attestations
   - Simulates Secure Enclave by generating ephemeral P 256 keys
   - Signs `sha256(i64_be(lat) || i64_be(lon) || i64_be(timestamp) || nonce)`
   - Outputs JSON with embedded public key and ECDSA signature

3. **`attestation_verifier`**: Verifies attestations and enforces constraints
   - Recovers and validates P 256 signatures
   - Supports three constraint types:
     - **Bounding Box**: Rectangular region (min/max lat/lon)
     - **Circle**: Haversine distance based radius check
     - **Polygon**: Point in polygon containment (using `geo` crate)



### Run

**Build all crates:**
```bash
cargo build
```

**Generate an attestation:**
```bash
cargo run -p attestation_mock_client -- gen \
  --lat-deg 37.7749 \
  --lon-deg=-122.4194 \
  --out att.json
```

**Verify signature + bounding box constraint:**
```bash
cargo run -p attestation_verifier -- bbox \
  --attestation att.json \
  --bbox="37.70,-122.52,37.82,-122.35"
# Output: signature_ok: true, constraint: bbox, satisfied: true
```

**Verify signature + circle constraint (5 km radius):**
```bash
cargo run -p attestation_verifier -- circle \
  --attestation att.json \
  --circle="37.7749,-122.4194,5000"
# Output: signature_ok: true, constraint: circle, satisfied: true
```

**Verify signature + polygon constraint:**
```bash
echo '[[37.77,-122.43],[37.80,-122.43],[37.80,-122.40],[37.77,-122.40],[37.77,-122.43]]' > polygon.json
cargo run -p attestation_verifier -- polygon \
  --attestation att.json \
  --polygon polygon.json
# Output: signature_ok: true, constraint: polygon, satisfied: true


### Notes

**Coordinate Scaling (1e7)**
- GPS decimals (float) → integers (i64) for deterministic hashing
- 1e7 scale = ~1.1 cm precision; sufficient for region level claims
- Prevents signature ambiguity (e.g., 37.7749 vs 37.77490)

**ECDSA P256 (ES256)**
- Apple App Attest standard; aligns with real iOS implementation
- Signature: fixed 64 byte `r || s` format (32 bytes each)
- Easier cryptography compared to RSA; modern and widely supported

**Mock Attestation Object**
- Real App Attest would include Apple signed certificate chain


- **Apple DeviceCheck/App Attest**: https://developer.apple.com/documentation/devicecheck
- **ECDSA P256**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- **geo Crate**: https://docs.rs/geo/latest/geo/
- **SP1 Documentation**: https://docs.succinct.xyz/docs/sp1/