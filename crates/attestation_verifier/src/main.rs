use std::path::PathBuf;

use attestation_types::Attestation;
use attestation_verifier::{bbox_contains, circle_contains, polygon_contains, verify_attestation};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "attestation-verify")] 
#[command(about = "Verify mock iOS-like location attestation and constraints")] 
struct Cli {
    /// Scale factor used for lat/lon integer encoding (default 1e7)
    #[arg(long, default_value_t = 10_000_000i64)]
    scale: i64,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Verify attestation against bounding box constraint
    Bbox {
        #[arg(long)] attestation: PathBuf,
        /// min_lat,min_lon,max_lat,max_lon (decimal degrees)
        #[arg(long)] bbox: String,
    },
    /// Verify attestation against circular constraint
    Circle {
        #[arg(long)] attestation: PathBuf,
        /// center_lat,center_lon,radius_meters
        #[arg(long)] circle: String,
    },
    /// Verify attestation against polygon constraint
    Polygon {
        #[arg(long)] attestation: PathBuf,
        /// Path to JSON array of [lat, lon] pairs for exterior ring
        #[arg(long)] polygon: PathBuf,
    },
}

fn parse_bbox(s: &str) -> anyhow::Result<(f64, f64, f64, f64)> {
    let parts: Vec<_> = s.split(',').collect();
    if parts.len() != 4 { anyhow::bail!("expected 4 comma-separated values"); }
    Ok((parts[0].parse()?, parts[1].parse()?, parts[2].parse()?, parts[3].parse()?))
}

fn parse_circle(s: &str) -> anyhow::Result<(f64, f64, f64)> {
    let parts: Vec<_> = s.split(',').collect();
    if parts.len() != 3 { anyhow::bail!("expected 3 comma-separated values"); }
    Ok((parts[0].parse()?, parts[1].parse()?, parts[2].parse()?))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Bbox { attestation, bbox } => {
            let data = std::fs::read_to_string(attestation)?;
            let att: Attestation = serde_json::from_str(&data)?;
            let verified = verify_attestation(&att, cli.scale)?;
            let (min_lat, min_lon, max_lat, max_lon) = parse_bbox(&bbox)?;
            let ok = bbox_contains(verified.lat_deg, verified.lon_deg, min_lat, min_lon, max_lat, max_lon);
            println!("signature_ok: true, constraint: bbox, satisfied: {}", ok);
        }
        Commands::Circle { attestation, circle } => {
            let data = std::fs::read_to_string(attestation)?;
            let att: Attestation = serde_json::from_str(&data)?;
            let verified = verify_attestation(&att, cli.scale)?;
            let (clat, clon, r) = parse_circle(&circle)?;
            let ok = circle_contains(verified.lat_deg, verified.lon_deg, clat, clon, r);
            println!("signature_ok: true, constraint: circle, satisfied: {}", ok);
        }
        Commands::Polygon { attestation, polygon } => {
            let data = std::fs::read_to_string(attestation)?;
            let att: Attestation = serde_json::from_str(&data)?;
            let verified = verify_attestation(&att, cli.scale)?;
            let coords: Vec<[f64; 2]> = serde_json::from_str(&std::fs::read_to_string(polygon)?)?;
            let coords: Vec<(f64, f64)> = coords.into_iter().map(|a| (a[0], a[1])).collect();
            let ok = polygon_contains(verified.lat_deg, verified.lon_deg, &coords);
            println!("signature_ok: true, constraint: polygon, satisfied: {}", ok);
        }
    }

    Ok(())
}
