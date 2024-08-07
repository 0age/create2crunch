use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use alloy_primitives::hex::FromHex;
use alloy_primitives::B256;

#[derive(Debug)]
struct AddressEntry {
    salt: B256,
    address: String,
    rarity_score: u32,
}

fn main() -> io::Result<()> {
    let path = Path::new("efficient_addresses.txt");
    let file = File::open(&path)?;
    let reader = io::BufReader::new(file);

    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(" => ").collect();

        if parts.len() == 3 {
            let salt = hex_to_b256(parts[0]);
            let address = parts[1].to_string();
            let rarity_score = parts[2].trim().parse::<u32>().unwrap_or(0);

            let entry = AddressEntry {
                salt,
                address,
                rarity_score
            };
            entries.push(entry);
        }
    }

    let highest_rarity_entries = find_highest_rarity_entries(&entries);
    for entry in highest_rarity_entries {
        println!("{:?}", entry);
    }

    Ok(())
}

fn find_highest_rarity_entries(entries: &[AddressEntry]) -> Vec<&AddressEntry> {
    if entries.is_empty() {
        return Vec::new();
    }

    let max_score = entries.iter().map(|e| e.rarity_score).max().unwrap();

    entries.iter()
        .filter(|e| e.rarity_score == max_score)
        .collect()
}

fn hex_to_b256(hex_str: &str) -> B256 {
    let hex_str = hex_str.trim_start_matches("0x");
    B256::from_hex(hex_str).expect("Failed to convert salt string to b256")
}