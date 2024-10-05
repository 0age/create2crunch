use create2crunch::CliArgsConfig;
use create2crunch::ConfigFile;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "Usage: {} [config_file] or provide necessary arguments",
            args[0]
        );
        process::exit(1);
    }

    // Check if the first argument is a config file
    let config_arg = &args[1];
    let config_path = std::path::Path::new(config_arg);

    // Check if the config file exists
    if config_path.exists() {
        run_with_config_file(&args);
    } else {
        run_with_args(&args);
    }
}

// Run create2crunch with args
fn run_with_args(args: &[String]) {
    // Parse the args
    let config = CliArgsConfig::new(args).unwrap_or_else(|err| {
        eprintln!("Failed parsing arguments: {err}");
        process::exit(1);
    });

    if config.gpu_device == 255 {
        if let Err(e) = create2crunch::cpu(config.to_run_config()) {
            eprintln!("CPU application error: {e}");
            process::exit(1);
        }
    } else if let Err(e) = create2crunch::gpu(config.to_run_config(), config.gpu_device) {
        eprintln!("GPU application error: {e}");
        process::exit(1);
    }
}

// Run create2crunch with config file
fn run_with_config_file(args: &[String]) {
    let config_arg = &args[1];

    // Load the configuration file
    let config_file = ConfigFile::new(config_arg).unwrap_or_else(|err| {
        eprintln!("Failed to load configuration file: {}", err);
        process::exit(1);
    });

    // Process the configuration
    if let Err(e) = create2crunch::process_config(config_file) {
        eprintln!("Configuration processing error: {e}");
        process::exit(1);
    }
}
