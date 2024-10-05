use alloy_primitives::hex;

use crate::RunConfig;

/// Requires three hex-encoded arguments: the address of the contract that will
/// be calling CREATE2, the address of the caller of said contract *(assuming
/// the contract calling CREATE2 has frontrunning protection in place - if not
/// applicable to your use-case you can set it to the null address)*, and the
/// keccak-256 hash of the bytecode that is provided by the contract calling
/// CREATE2 that will be used to initialize the new contract. An additional set
/// of three optional values may be provided: a device to target for OpenCL GPU
/// search, a threshold for leading zeroes to search for, and a threshold for
/// total zeroes to search for.
pub struct CliArgsConfig {
    pub factory_address: [u8; 20],
    pub calling_address: [u8; 20],
    pub init_code_hash: [u8; 32],
    pub gpu_device: u8,
    pub leading_zeroes_threshold: u8,
    pub total_zeroes_threshold: u8,
}

/// Validate the provided arguments and construct the Config struct.
impl CliArgsConfig {
    pub fn new(args: &[String]) -> Result<Self, &'static str> {
        // get args, skipping first arg (program name)
        let mut args_iter = args.iter();
        args_iter.next();

        let Some(factory_address_string) = args_iter.next() else {
            return Err("didn't get a factory_address argument");
        };
        let Some(calling_address_string) = args_iter.next() else {
            return Err("didn't get a calling_address argument");
        };
        let Some(init_code_hash_string) = args_iter.next() else {
            return Err("didn't get an init_code_hash argument");
        };

        let gpu_device_string = match args_iter.next() {
            Some(arg) => arg.clone(),
            None => String::from("255"), // indicates that CPU will be used.
        };
        let leading_zeroes_threshold_string = match args_iter.next() {
            Some(arg) => arg.clone(),
            None => String::from("3"),
        };
        let total_zeroes_threshold_string = match args_iter.next() {
            Some(arg) => arg.clone(),
            None => String::from("5"),
        };

        // convert main arguments from hex string to vector of bytes
        let Ok(factory_address_vec) = hex::decode(factory_address_string) else {
            return Err("could not decode factory address argument");
        };
        let Ok(calling_address_vec) = hex::decode(calling_address_string) else {
            return Err("could not decode calling address argument");
        };
        let Ok(init_code_hash_vec) = hex::decode(init_code_hash_string) else {
            return Err("could not decode initialization code hash argument");
        };

        // convert from vector to fixed array
        let Ok(factory_address) = factory_address_vec.try_into() else {
            return Err("invalid length for factory address argument");
        };
        let Ok(calling_address) = calling_address_vec.try_into() else {
            return Err("invalid length for calling address argument");
        };
        let Ok(init_code_hash) = init_code_hash_vec.try_into() else {
            return Err("invalid length for initialization code hash argument");
        };

        // convert gpu arguments to u8 values
        let Ok(gpu_device) = gpu_device_string.parse::<u8>() else {
            return Err("invalid gpu device value");
        };
        let Ok(leading_zeroes_threshold) = leading_zeroes_threshold_string.parse::<u8>() else {
            return Err("invalid leading zeroes threshold value supplied");
        };
        let Ok(total_zeroes_threshold) = total_zeroes_threshold_string.parse::<u8>() else {
            return Err("invalid total zeroes threshold value supplied");
        };

        if leading_zeroes_threshold > 20 {
            return Err("invalid value for leading zeroes threshold argument. (valid: 0..=20)");
        }
        if total_zeroes_threshold > 20 && total_zeroes_threshold != 255 {
            return Err("invalid value for total zeroes threshold argument. (valid: 0..=20 | 255)");
        }

        Ok(Self {
            factory_address,
            calling_address,
            init_code_hash,
            gpu_device,
            leading_zeroes_threshold,
            total_zeroes_threshold,
        })
    }

    // Map a cli args to a run config
    pub fn to_run_config(&self) -> RunConfig {
        RunConfig {
            factory_address: self.factory_address,
            calling_address: self.calling_address,
            init_code_hash: self.init_code_hash,
            leading_zeroes_threshold: self.leading_zeroes_threshold,
            total_zeroes_threshold: self.total_zeroes_threshold,
            early_stop: false,
        }
    }
}
