use alloy_primitives::{hex, keccak256, Address};
use serde::Deserialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::Path;

use crate::RunConfig;

// Config file once parsed
pub struct ConfigFile {
    pub bin_folder: String,
    pub factory_address: [u8; 20],
    pub calling_address: [u8; 20],
    pub gpu_device: u8,
    pub targets: Vec<Target>,
}

// Config file structure
#[derive(Deserialize)]
struct ConfigFileRaw {
    bin_folder: String,
    factory_address: String,
    calling_address: String,
    gpu_device: Option<u8>,
    targets: Vec<Target>,
}

// Config smart contract target structure
#[derive(Deserialize, Clone)]
pub struct Target {
    pub name: String,
    pub placeholder_name: Option<String>,
    #[serde(default)]
    pub stop_thresholds: Option<StopThresholds>,
}

// Config smart contract target stop thresholds (which requirements do we need to stop the crunching and move on)
#[derive(Deserialize, Clone)]
pub struct StopThresholds {
    pub leading_zeroes: Option<u8>,
    pub total_zeroes: Option<u8>,
}

impl ConfigFile {
    pub fn new(path: &str) -> Result<Self, Box<dyn Error>> {
        let config_content = fs::read_to_string(path)?;
        let config: ConfigFileRaw = toml::from_str(&config_content)?;

        // Check if bin folder exists
        if !Path::new(&config.bin_folder).exists() {
            return Err(format!("Bin folder '{}' does not exist", &config.bin_folder).into());
        }

        // Parse the gpu device (if not specified, default to 255)
        let gpu_device = config.gpu_device.unwrap_or(255);

        // Parse a few hex stuff
        let Ok(factory_address_vec) = hex::decode(config.factory_address) else {
            return Err("could not decode factory address argument".into());
        };
        let Ok(calling_address_vec) = hex::decode(config.calling_address) else {
            return Err("could not decode calling address argument".into());
        };

        // Convert from vector to fixed array
        let Ok(factory_address) = factory_address_vec.try_into() else {
            return Err("invalid length for factory address argument".into());
        };
        let Ok(calling_address) = calling_address_vec.try_into() else {
            return Err("invalid length for calling address argument".into());
        };

        // Build the parsed config file
        let parsed_config = ConfigFile {
            bin_folder: config.bin_folder,
            factory_address,
            calling_address,
            gpu_device,
            targets: config.targets,
        };

        // Iterate over each target
        for target in &parsed_config.targets {
            // Construct the path to the bin file
            let bin_file_path = Path::new(&parsed_config.bin_folder).join(&target.name);

            // Check if the bin file exists
            if !bin_file_path.exists() {
                return Err(
                    format!("Bin file '{}' does not exist", bin_file_path.display()).into(),
                );
            }
        }

        // Stop points validation
        parsed_config.validate_stop_points()?;

        // Placeholder validation
        parsed_config.validate_placeholders()?;

        Ok(parsed_config)
    }

    // Validate the placeholders in the bin files
    fn validate_placeholders(&self) -> Result<(), String> {
        let placeholder_pattern = regex::Regex::new(r"\$\{(\w+)\}").unwrap();

        for target in &self.targets {
            // Construct the path to the bin file
            let bin_file_path = Path::new(&self.bin_folder).join(&target.name);

            let bin_content = std::fs::read_to_string(&bin_file_path)
                .map_err(|e| format!("Failed to read bin file {}", e))?;

            // Ensure the placeholder referenced in the bin file exists in the target configuration
            for caps in placeholder_pattern.captures_iter(&bin_content) {
                let placeholder = &caps[1];
                // Ensure the placeholder exists in some target configuration
                if !self
                    .targets
                    .iter()
                    .any(|target| target.placeholder_name.as_deref() == Some(placeholder))
                {
                    return Err(format!(
                        "Missing placeholder '{}' in the target configuration",
                        placeholder
                    ));
                }

                // Ensure that the placeholder isn't the one of the target itself (otherwise it would create a circular dependency)
                if target.placeholder_name.as_deref() == Some(placeholder) {
                    return Err(format!(
                        "Circular dependency detected for placeholder '{}'",
                        placeholder
                    ));
                }
            }
        }
        Ok(())
    }

    /// Ensure every target has at least one stop point (leading zeroes or total zeroes)
    fn validate_stop_points(&self) -> Result<(), String> {
        for target in &self.targets {
            if let Some(stop_thresholds) = &target.stop_thresholds {
                if stop_thresholds.leading_zeroes.is_none()
                    && stop_thresholds.total_zeroes.is_none()
                {
                    return Err(format!(
                        "Target '{}' does not have any stop points defined",
                        target.name
                    ));
                }
            } else {
                return Err(format!(
                    "Target '{}' does not have any stop points defined",
                    target.name
                ));
            }
        }
        Ok(())
    }

    // Map a config file to a run config, with a target and the current placeholders
    pub fn to_run_config(
        &self,
        target: &Target,
        placeholders: &HashMap<String, Address>,
    ) -> RunConfig {
        let bin_file_path = Path::new(&self.bin_folder).join(&target.name);
        let mut bin_content = fs::read_to_string(&bin_file_path).unwrap();

        // Replace the placeholders in the bin file with the actual values
        for (placeholder, value) in placeholders {
            let placeholder = format!("${{{}}}", placeholder);
            bin_content = bin_content.replace(&placeholder, &hex::encode(&value));
        }

        // Parse the bin content as hex
        let hex_bin = hex::decode(bin_content).unwrap();

        // The init code hash is a keccak256 hash of the bin file content as hex (using the keccak256 crate)ap();
        let init_hash = keccak256(hex_bin).to_vec().try_into().unwrap();

        // Get the stop trehsolds for the target
        let stop_thresholds = target.stop_thresholds.as_ref().unwrap();

        RunConfig {
            factory_address: self.factory_address,
            calling_address: self.calling_address,
            init_code_hash: init_hash,
            leading_zeroes_threshold: stop_thresholds.leading_zeroes.unwrap(),
            total_zeroes_threshold: stop_thresholds.total_zeroes.unwrap(),
            early_stop: true,
        }
    }

    // Check if we got everything needed to process a target
    pub fn can_process(&self, target: &Target, placeholders: &HashMap<String, Address>) -> bool {
        let bin_file_path = Path::new(&self.bin_folder).join(&target.name);
        let bin_content = fs::read_to_string(&bin_file_path).unwrap();

        // Check if the content contain placeholders not in the placeholders map
        let placeholder_pattern = regex::Regex::new(r"\$\{(\w+)\}").unwrap();
        for caps in placeholder_pattern.captures_iter(&bin_content) {
            let placeholder = &caps[1];
            if !placeholders.contains_key(placeholder) {
                return false;
            }
        }

        // Otherwise, all good
        return true;
    }
}
