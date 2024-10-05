use alloy_primitives::{hex, Address};
use fs4::FileExt;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::SystemTime;

use crate::{cpu, gpu, ConfigFile};

/// Process the configuration file
/// todo: Maybve when we reach the end try to increase the treesholds and rerun it again? To have a continuios execution?
pub fn process_config(config_file: ConfigFile) -> Result<(), Box<dyn std::error::Error>> {
    // (create if necessary) and open a file where found salts per contracts will be written
    let file = output_file();

    // Map to store computed addresses by placeholder name
    let mut computed_addresses: HashMap<String, Address> = HashMap::new();

    // Targets that are yet to be processed
    let mut remaining_targets = config_file.targets.clone();

    // Write an header to our file with the start timestamp and number of targets
    let header = format!(
        "Start: {}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
    );
    file.lock_exclusive().expect("Couldn't lock file.");
    writeln!(&file, "{header}").expect("Couldn't write to `address_per_contracts.txt` file.");
    file.unlock().expect("Couldn't unlock file.");

    // Loop until all targets are processed or no progress is made
    while !remaining_targets.is_empty() {
        let initial_len = remaining_targets.len();
        let mut processed_indices = Vec::new();

        // Iterate over each target
        for (i, target) in remaining_targets.iter().enumerate() {
            // Check if this target can be processed
            if config_file.can_process(target, &computed_addresses) {
                println!("Processing contract: {}", target.name);

                // Construct RunConfig
                let run_config = config_file.to_run_config(target, &computed_addresses);
                let init_hash = hex::encode(run_config.init_code_hash);

                // Decide whether to use CPU or GPU
                let results = if config_file.gpu_device == 255 {
                    cpu(run_config)?
                } else {
                    gpu(run_config, config_file.gpu_device)?
                };

                // Get the addresses with the higher reward (string but can be converted to u8)
                let result = results
                    .iter()
                    .max_by_key(|address| &address.reward)
                    .unwrap();

                // Craft the file output (target bin, init hash, salt, address, reward)
                let output = format!(
                    "{} - {:?}: {} => {} : {} ({} / {})",
                    target.name,
                    init_hash,
                    result.salt,
                    result.address,
                    result.reward,
                    result.leading,
                    result.total
                );

                // Write the address output
                file.lock_exclusive().expect("Couldn't lock file.");
                writeln!(&file, "{output}")
                    .expect("Couldn't write to `address_per_contracts.txt` file.");
                file.unlock().expect("Couldn't unlock file.");

                // Move the `efficient_addresses.txt`` file to an `efficient_addresses.{target.name}.txt`` file
                let efficient_addresses_file = format!("efficient_addresses.{}.txt", target.name);
                std::fs::rename("efficient_addresses.txt", efficient_addresses_file)
                    .expect("Couldn't rename file.");

                // If this target defines a placeholder, store the computed address
                if let Some(placeholder_name) = &target.placeholder_name {
                    computed_addresses.insert(placeholder_name.clone(), result.address);
                }

                // Mark this target as processed
                processed_indices.push(i);
            }
        }

        // Remove processed targets from the list
        for &i in processed_indices.iter().rev() {
            remaining_targets.remove(i);
        }

        // If no targets were processed in this iteration, there is a circular dependency or missing placeholder
        if remaining_targets.len() == initial_len {
            return Err("Unable to process all targets".into());
        }
    }

    let footer = format!(
        "End: {}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_secs()
    );
    file.lock_exclusive().expect("Couldn't lock file.");
    writeln!(&file, "{footer}").expect("Couldn't write to `address_per_contracts.txt` file.");
    file.unlock().expect("Couldn't unlock file.");

    Ok(())
}

#[track_caller]
fn output_file() -> File {
    OpenOptions::new()
        .append(true)
        .create(true)
        .read(true)
        .open("address_per_contracts.txt")
        .expect("Could not create or open `address_per_contracts.txt` file.")
}
