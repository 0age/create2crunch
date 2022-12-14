mod reward;

extern crate byteorder;
extern crate console;
extern crate fs2;
extern crate hex;
extern crate itertools;
extern crate ocl;
extern crate ocl_extras;
extern crate rand;
extern crate rayon;
extern crate separator;
extern crate terminal_size;
extern crate tiny_keccak;

use std::error::Error;
use std::i64;
use std::io::prelude::*;
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use console::Term;
use fs2::FileExt;
use hex::FromHex;
use itertools::Itertools;
use ocl::{ProQue, Buffer, MemFlags, Platform, Device, Context, Queue, Program};
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use separator::Separatable;
use terminal_size::{Width, Height, terminal_size};
use tiny_keccak::Keccak;

// workset size (tweak this!)
const WORK_SIZE: usize = 0x4000000; // max. 0x15400000 to abs. max 0xffffffff

const INTERVAL: u64 = 0x100000000;
const WORK_FACTOR: u128 = (WORK_SIZE as u128) / 1_000_000;
const ZERO_BYTE: u8 = 0x00;
const EIGHT_ZERO_BYTES: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
const CONTROL_CHARACTER: u8 = 0xff;
const ZERO_REWARD: &str = "0";
const MAX_INCREMENTER: u64 = 0xffffffffffff;

static KERNEL_SRC: &'static str = include_str!("./kernels/keccak256.cl");

/// Requires three hex-encoded arguments: the address of the contract that will
/// be calling CREATE2, the address of the caller of said contract *(assuming
/// the contract calling CREATE2 has frontrunning protection in place - if not
/// applicable to your use-case you can set it to the null address)*, and the
/// keccak-256 hash of the bytecode that is provided by the contract calling
/// CREATE2 that will be used to initialize the new contract. An additional set
/// of three optional values may be provided: a device to target for OpenCL GPU
/// search, a threshold for leading zeroes to search for, and a threshold for
/// total zeroes to search for.
pub struct Config {
    pub factory_address: [u8; 20],
    pub calling_address: [u8; 20],
    pub init_code_hash: [u8; 32],
    pub gpu_device: u8,
    pub leading_zeroes_threshold: u8,
    pub total_zeroes_threshold: u8,
}

/// Validate the provided arguments and construct the Config struct.
impl Config {
    pub fn new(mut args: std::env::Args) -> Result<Self, &'static str> {
        // get args, skipping first arg (program name)
        args.next();

        let mut factory_address_string = match args.next() {
            Some(arg) => arg,
            None => return Err("didn't get a factory_address argument."),
        };

        let mut calling_address_string = match args.next() {
            Some(arg) => arg,
            None => return Err("didn't get a calling_address argument."),
        };

        let mut init_code_hash_string = match args.next() {
            Some(arg) => arg,
            None => return Err("didn't get an init_code_hash argument."),
        };

        let gpu_device_string = match args.next() {
            Some(arg) => arg,
            None => String::from("255"), // indicates that CPU will be used.
        };

        let leading_zeroes_threshold_string= match args.next() {
            Some(arg) => arg,
            None => String::from("3"),
        };

        let total_zeroes_threshold_string = match args.next() {
            Some(arg) => arg,
            None => String::from("5"),
        };

        // strip 0x from args if applicable
        if factory_address_string.starts_with("0x") {
            factory_address_string = without_prefix(factory_address_string)
        }

        if calling_address_string.starts_with("0x") {
            calling_address_string = without_prefix(calling_address_string)
        }

        if init_code_hash_string.starts_with("0x") {
            init_code_hash_string = without_prefix(init_code_hash_string)
        }

        // convert main arguments from hex string to vector of bytes
        let factory_address_vec: Vec<u8> = match Vec::from_hex(
            &factory_address_string
        ) {
            Ok(t) => t,
            Err(_) => {
                return Err("could not decode factory address argument.")
            }
        };

        let calling_address_vec: Vec<u8> = match Vec::from_hex(
            &calling_address_string
        ) {
            Ok(t) => t,
            Err(_) => {
                return Err("could not decode calling address argument.")
            }
        };

        let init_code_hash_vec: Vec<u8> = match Vec::from_hex(
            &init_code_hash_string
        ) {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "could not decode initialization code hash argument."
                )
            }
        };

        // validate length of each argument (20, 20, 32)
        if factory_address_vec.len() != 20 {
            return Err("invalid length for factory address argument.")
        }

        if calling_address_vec.len() != 20 {
            return Err("invalid length for calling address argument.")
        }

        if init_code_hash_vec.len() != 32 {
            return Err("invalid length for initialization code hash argument.")
        }

        // convert from vector to fixed array
        let factory_address = to_fixed_20(factory_address_vec);
        let calling_address = to_fixed_20(calling_address_vec);
        let init_code_hash = to_fixed_32(init_code_hash_vec);

        // convert gpu arguments to u8 values
        let gpu_device: u8 = match gpu_device_string
                                               .parse::<u8>() {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "invalid gpu device value."
                )
            }
        };

        let leading_zeroes_threshold = match leading_zeroes_threshold_string
                                               .parse::<u8>() {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "invalid leading zeroes threshold value supplied."
                )
            }
        };

        let total_zeroes_threshold = match total_zeroes_threshold_string
                                             .parse::<u8>() {
            Ok(t) => t,
            Err(_) => {
                return Err(
                    "invalid total zeroes threshold value supplied."
                )
            }
        };

        if leading_zeroes_threshold > 20 {
            return Err("invalid value for leading zeroes threshold argument. (valid: 0 .. 20)")
        }

        if total_zeroes_threshold > 20 && total_zeroes_threshold != 255  {
            return Err("invalid value for total zeroes threshold argument. (valid: 0 .. 20, 255)")
        }

        // return the config object
        Ok(
          Self {
            factory_address,
            calling_address,
            init_code_hash,
            gpu_device,
            leading_zeroes_threshold,
            total_zeroes_threshold
          }
        )
    }
}

/// Given a Config object with a factory address, a caller address, and a
/// keccak-256 hash of the contract initialization code, search for salts that
/// will enable the factory contract to deploy a contract to a gas-efficient
/// address via CREATE2.
///
/// The 32-byte salt is constructed as follows:
///   - the 20-byte calling address (to prevent frontrunning)
///   - a random 6-byte segment (to prevent collisions with other runs)
///   - a 6-byte nonce segment (incrementally stepped through during the run)
///
/// When a salt that will result in the creation of a gas-efficient contract
/// address is found, it will be appended to `efficient_addresses.txt` along
/// with the resultant address and the "value" (i.e. approximate rarity) of the
/// resultant address.
pub fn cpu(config: Config) -> Result<(), Box<dyn Error>> {
    // (create if necessary) and open a file where found salts will be written
    let file = OpenOptions::new()
                 .append(true)
                 .create(true)
                 .open("efficient_addresses.txt")
                 .expect(
                   "Could not create or open `efficient_addresses.txt` file."
                 );

    // create object for computing rewards (relative rarity) for a given address
    let rewards = reward::Reward::new();

    // set "footer" of hash message using initialization code hash from config
    let footer: [u8; 32] = config.init_code_hash;

    // create a random number generator
    let mut rng = thread_rng();

    // begin searching for addresses
    loop {
        // create a random 6-byte salt using the random number generator
        let salt_random_segment = rng.gen_iter::<u8>()
                                    .take(6)
                                    .collect::<Vec<u8>>();

        // header: 0xff ++ factory ++ caller ++ salt_random_segment (47 bytes)
        let mut header_vec: Vec<u8> = vec![CONTROL_CHARACTER];
        header_vec.extend(config.factory_address.iter());
        header_vec.extend(config.calling_address.iter());
        header_vec.extend(salt_random_segment);

        // convert the header vector to a fixed-length array
        let header: [u8; 47] = to_fixed_47(&header_vec);

        // create new hash object
        let mut hash_header = Keccak::new_keccak256();

        // update hash with header
        hash_header.update(&header);

        // iterate over a 6-byte nonce and compute each address
        (0..MAX_INCREMENTER)
          .into_par_iter() // parallelization
          .map(|x| u64_to_fixed_6(&x)) // convert int nonces to fixed arrays
          .for_each(|salt_incremented_segment| {
            // clone the partially-hashed object
            let mut hash = hash_header.clone();

            // update with body and footer (total: 38 bytes)
            hash.update(&salt_incremented_segment);
            hash.update(&footer);

            // hash the payload and get the result
            let mut res: [u8; 32] = [0; 32];
            hash.finalize(&mut res);

            // get the total zero bytes associated with the address
            let total = res
                          .iter()
                          .dropping(12)
                          .filter(|&n| *n == ZERO_BYTE)
                          .count();

            // only proceed if there are at least three zero bytes
            if total > 2 {
                // get the leading zero bytes associated with the address
                let mut leading = 0;

                // iterate through each byte of address and count zero bytes
                for (i, b) in res.iter().dropping(12).enumerate() {
                    if b != &ZERO_BYTE {
                        leading = i; // set leading on finding non-zero byte
                        break;       // stop searching upon locating
                    }
                }

                // look up the reward amount
                let key = leading * 20 + total;
                let reward_amount = rewards.get(&key);

                // proceed if an efficient address has been found
                if reward_amount != ZERO_REWARD {
                    // truncate first 12 bytes from the hash to derive address
                    let mut address_bytes: [u8; 20] = Default::default();
                    address_bytes.copy_from_slice(&res[12..]);

                    // get the address that results from the hash
                    let address_hex_string = hex::encode(&address_bytes);
                    let address = format!("{}", &address_hex_string);

                    // get the full salt used to create the address
                    let header_hex_string = hex::encode(&header_vec);
                    let body_hex_string = hex::encode(salt_incremented_segment
                                                        .to_vec());
                    let full_salt = format!(
                      "0x{}{}",
                      &header_hex_string[42..],
                      &body_hex_string
                    );

                    // encode address and set up a variable for the checksum
                    let address_encoded = address.as_bytes();
                    let mut checksum_address = "0x".to_string();

                    // create new hash object for computing the checksum
                    let mut checksum_hash = Keccak::new_keccak256();

                    // update with utf8-encoded address (total: 20 bytes)
                    checksum_hash.update(&address_encoded);

                    // hash the payload and get the result
                    let mut checksum_res: [u8; 32] = [0; 32];
                    checksum_hash.finalize(&mut checksum_res);
                    let address_hash = hex::encode(checksum_res);

                    // compute the address checksum using the above hash
                    for nibble in 0..address.len() {
                        let hash_character = i64::from_str_radix(
                          &address_hash
                            .chars()
                            .nth(nibble)
                            .unwrap()
                            .to_string(),
                          16
                        ).unwrap();
                        let character = address.chars().nth(nibble).unwrap();
                        if hash_character > 7 {
                            checksum_address = format!(
                              "{}{}",
                              checksum_address,
                              character.to_uppercase().to_string()
                            );
                        } else {
                            checksum_address = format!(
                              "{}{}",
                              checksum_address,
                              character.to_string()
                            );
                        }
                    }

                    // display the salt and the address.
                    let output = format!(
                      "{} => {} => {}",
                      full_salt,
                      checksum_address,
                      reward_amount
                    );
                    println!("{}", &output);

                    // create a lock on the file before writing
                    file.lock_exclusive().expect("Couldn't lock file.");

                    // write the result to file
                    writeln!(&file, "{}", &output).expect(
                      "Couldn't write to `efficient_addresses.txt` file."
                    );

                    // release the file lock
                    file.unlock().expect("Couldn't unlock file.")
                }
            }
        });
    }
}

/// Given a Config object with a factory address, a caller address, a keccak-256
/// hash of the contract initialization code, and a device ID, search for salts
/// using OpenCL that will enable the factory contract to deploy a contract to a
/// gas-efficient address via CREATE2. This method also takes threshold values
/// for both leading zero bytes and total zero bytes - any address that does not
/// meet or exceed the threshold will not be returned. Default threshold values
/// are three leading zeroes or five total zeroes.
///
/// The 32-byte salt is constructed as follows:
///   - the 20-byte calling address (to prevent frontrunning)
///   - a random 4-byte segment (to prevent collisions with other runs)
///   - a 4-byte segment unique to each work group running in parallel
///   - a 4-byte nonce segment (incrementally stepped through during the run)
///
/// When a salt that will result in the creation of a gas-efficient contract
/// address is found, it will be appended to `efficient_addresses.txt` along
/// with the resultant address and the "value" (i.e. approximate rarity) of the
/// resultant address.
///
/// This method is still highly experimental and could almost certainly use
/// further optimization - contributions are more than welcome!
pub fn gpu(config: Config) -> ocl::Result<()> {
    println!(
      "Setting up experimental OpenCL miner using device {}...",
      config.gpu_device
    );

    // (create if necessary) and open a file where found salts will be written
    let file = OpenOptions::new()
                 .append(true)
                 .create(true)
                 .open("efficient_addresses.txt")
                 .expect(
                   "Could not create or open `efficient_addresses.txt` file."
                 );

    // create object for computing rewards (relative rarity) for a given address
    let rewards = reward::Reward::new();

    // track how many addresses have been found and information about them
    let mut found: u64 = 0;
    let mut found_list: Vec<String> = vec![];

    // set up a controller for terminal output
    let term = Term::stdout();

    // set up a platform to use
    let platform = Platform::default();

    // set up the device to use
    let device = Device::by_idx_wrap(platform, config.gpu_device as usize)?;

    // set up the context to use
    let context = Context::builder()
                    .platform(platform)
                    .devices(device.clone())
                    .build()?;
    
    // get factory, caller, and initialization code hash from config object
    let factory: [u8; 20] = config.factory_address;
    let caller: [u8; 20] = config.calling_address;
    let init_hash: [u8; 32] = config.init_code_hash;

    // generate the kernel source code with the define macros
    let kernel_src = &format!(
        "{}\n{}\n{}\n#define LEADING_ZEROES {}\n#define TOTAL_ZEROES {}\n{}",
        factory
            .iter()
            .enumerate()
            .map(|(i, x)| format!("#define S_{} {}u\n", i + 1, x))
            .collect::<String>(),
        caller
            .iter()
            .enumerate()
            .map(|(i, x)| format!("#define S_{} {}u\n", i + 21, x))
            .collect::<String>(),
        init_hash
            .iter()
            .enumerate()
            .map(|(i, x)| format!("#define S_{} {}u\n", i + 53, x))
            .collect::<String>(),
        config.leading_zeroes_threshold,
        config.total_zeroes_threshold,
        KERNEL_SRC
    );

    // set up the program to use
    let program = Program::builder()
                    .devices(device)
                    .src(kernel_src)
                    .build(&context)?;

    // set up the queue to use
    let queue = Queue::new(&context, device, None)?;

    // set up the "proqueue" (or amalgamation of various elements) to use
    let ocl_pq = ProQue::new(context, queue, program, Some(WORK_SIZE));

    // create a random number generator
    let mut rng = thread_rng();


    // determine the start time
    let start_time: f64 = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as f64;

    // set up variables for tracking performance
    let mut rate: f64 = 0.0;
    let mut cumulative_nonce: u64 = 0;

    // begin searching for addresses
    loop {
        // create a random 4-byte salt using the random number generator
        let salt = rng.gen_iter::<u8>().take(4).collect::<Vec<u8>>();

        // construct the 4-byte message to hash, leaving last 8 of salt empty
        let message: [u8; 4] = to_fixed_4(&salt);

        // build a corresponding buffer for passing the message to the kernel
        let message_buffer = Buffer::builder()
                               .queue(ocl_pq.queue().clone())
                               .flags(MemFlags::new().read_only())
                               .len(4)
                               .copy_host_slice(&message)
                               .build()?;

        // reset nonce & create a buffer to view it in little-endian
        // for more uniformly distributed nonces, we shall initialize it to a random value
        let mut nonce: [u64; 1] = [rng.next_u64() & 0xffffffff00000000];
        let mut view_buf = [0; 8];

        // build a corresponding buffer for passing the nonce to the kernel
        let mut nonce_buffer = Buffer::builder()
                                 .queue(ocl_pq.queue().clone())
                                 .flags(MemFlags::new().read_only())
                                 .len(1)
                                 .copy_host_slice(&nonce)
                                 .build()?;

        // establish a buffer for nonces that result in desired addresses
        let mut solutions: Vec<u64> = vec![0; 1];
        let solutions_buffer: Buffer<u64> = Buffer::builder()
                                              .queue(ocl_pq.queue().clone())
                                              .flags(MemFlags::new().write_only())
                                              .len(1)
                                              .copy_host_slice(&solutions)
                                              .build()?;

        let mut previous_time: f64 = SystemTime::now()
                                  .duration_since(UNIX_EPOCH)
                                  .unwrap()
                                  .as_secs() as f64;

        // repeatedly enqueue kernel to search for new addresses
        loop {
            // calculate the current time
            let current_time: f64 = SystemTime::now()
                                      .duration_since(UNIX_EPOCH)
                                      .unwrap()
                                      .as_secs() as f64;

            // we don't want to print too fast
            let print_output: bool = current_time - previous_time > 0.99;
            previous_time = current_time;

            // clear the terminal screen
            if print_output {
                term.clear_screen()?;

                // get the total runtime and parse into hours : minutes : seconds
                let total_runtime = current_time - start_time;
                let total_runtime_hrs = *&total_runtime as u64 / (3600);
                let total_runtime_mins = (
                  *&total_runtime as u64 - &total_runtime_hrs * 3600
                ) / 60;
                let total_runtime_secs = &total_runtime - (
                  &total_runtime_hrs * 3600
                ) as f64 - (&total_runtime_mins * 60) as f64;

                // determine the number of attempts being made per second
                let work_rate: u128 = WORK_FACTOR * cumulative_nonce as u128;
                if total_runtime > 0.0 {
                    rate = 1.0 / total_runtime;
                }

                // fill the buffer for viewing the properly-formatted nonce
                LittleEndian::write_u64(&mut view_buf, nonce[0]);


                // calculate the terminal height, defaulting to a height of ten rows
                let size = terminal_size();
                let height: u16;
                if let Some((Width(_w), Height(h))) = size {
                    height = h;
                } else {
                    height = 10;
                }

                // display information about the total runtime and work size
                term.write_line(&format!(
                  "total runtime: {}:{:02}:{:02} ({} cycles)\t\t\t\
                  work size per cycle: {}",
                  total_runtime_hrs,
                  total_runtime_mins,
                  total_runtime_secs,
                  cumulative_nonce,
                  WORK_SIZE.separated_string()
                ))?;    

                // display information about the attempt rate and found solutions
                term.write_line(&format!(
                  "rate: {:.2} million attempts per second\t\t\t\
                  total found this run: {}",
                  work_rate as f64 * rate,
                  &found
                ))?;    
                // display information about the current search criteria
                term.write_line(&format!(
                  "current search space: {}xxxxxxxx{:08x}\t\t\
                  threshold: {} leading or {} total zeroes",
                  hex::encode(&salt),
                  BigEndian::read_u64(&view_buf),
                  config.leading_zeroes_threshold,
                  config.total_zeroes_threshold
                ))?;

                // display recently found solutions based on terminal height
                let rows: usize = if height < 5 { 1 } else { (height - 4) as usize };
                let last_rows: Vec<String> = found_list
                                               .iter()
                                               .cloned()
                                               .rev()
                                               .take(rows)
                                               .collect();
                let ordered: Vec<String> = last_rows.iter().cloned().rev().collect();
                let recently_found = &ordered.join("\n");
                term.write_line(&recently_found)?;
            }

            // build the kernel and define the type of each buffer
            let kern = ocl_pq.kernel_builder("hashMessage")
                         .arg_named("message", None::<&Buffer<u8>>)
                         .arg_named("nonce", None::<&Buffer<u64>>)
                         .arg_named("solutions", None::<&Buffer<u64>>)
                         .build()?;

            // set each buffer
            kern.set_arg("message", Some(&message_buffer))?;
            kern.set_arg("nonce", Some(&nonce_buffer))?;
            kern.set_arg("solutions", &solutions_buffer)?;

            // enqueue the kernel
            unsafe { kern.enq()?; }

            // increment the cumulative nonce (does not reset after a match)
            cumulative_nonce += 1;

            // read the solutions from the device
            solutions_buffer.read(&mut solutions).enq()?;

            // if at least one solution is found, end the loop
            if solutions[0] != 0 {
                break;
            }

            // if no solution has yet been found, increment the nonce
            nonce[0] = (nonce[0] + (INTERVAL as u64)) & 0xffffffff00000000;

            // update the nonce buffer with the incremented nonce value
            nonce_buffer = Buffer::builder()
                             .queue(ocl_pq.queue().clone())
                             .flags(MemFlags::new().read_write())
                             .len(1)
                             .copy_host_slice(&nonce)
                             .build()?;
        }

        // iterate over each solution, first converting to a fixed array
        solutions
          .iter()
          .filter(|&i| *i != 0)
          .map(|i| u64_to_le_fixed_8(i))
          .for_each(|solution| {
            // proceed if a solution is found at the given location
            if &solution != &EIGHT_ZERO_BYTES {
                let mut solution_message: Vec<u8> = vec![
                  CONTROL_CHARACTER
                ];

                solution_message.extend(factory.iter());
                solution_message.extend(caller.iter());
                solution_message.extend(salt.iter());
                solution_message.extend(solution.iter());
                solution_message.extend(init_hash.iter());

                // create new hash object
                let mut hash = Keccak::new_keccak256();

                // update with header
                hash.update(&solution_message);

                // hash the payload and get the result
                let mut res: [u8; 32] = [0; 32];
                hash.finalize(&mut res);

                // get the total zero bytes associated with the address
                let total = res
                              .iter()
                              .dropping(12)
                              .filter(|&n| *n == ZERO_BYTE)
                              .count();

                // get the leading zero bytes associated with the address
                let mut leading = 0;

                // iterate through each byte of address and count zero bytes
                for (i, b) in res.iter().dropping(12).enumerate() {
                    if b != &ZERO_BYTE {
                        leading = i; // set leading on reaching non-zero byte
                        break; // stop on locating (unless it's null address!)
                    }
                }

                let key = leading * 20 + total;

                let mut address_bytes: [u8; 20] = Default::default();
                address_bytes.copy_from_slice(&res[12..]);

                // get the address that results from the hash
                let address_hex_string = hex::encode(&address_bytes);
                let address = format!("{}", &address_hex_string);

                // encode address and set up a variable for the checksum
                let address_encoded = address.as_bytes();
                let mut checksum_address = "0x".to_string();

                // create new hash object for computing the checksum
                let mut checksum_hash = Keccak::new_keccak256();

                // update with utf8-encoded address (total: 20 bytes)
                checksum_hash.update(&address_encoded);

                // hash the payload and get the result
                let mut checksum_res: [u8; 32] = [0; 32];
                checksum_hash.finalize(&mut checksum_res);
                let address_hash = hex::encode(checksum_res);

                // compute the checksum using the above hash
                for nibble in 0..address.len() {
                    let hash_character = i64::from_str_radix(
                      &address_hash
                        .chars()
                        .nth(nibble)
                        .unwrap()
                        .to_string(),
                      16
                    ).unwrap();
                    let character = address.chars().nth(nibble).unwrap();
                    if hash_character > 7 {
                        checksum_address = format!(
                          "{}{}",
                          checksum_address,
                          character.to_uppercase().to_string()
                        );
                    } else {
                        checksum_address = format!(
                          "{}{}",
                          checksum_address,
                          character.to_string()
                        );
                    }
                }

                let reward_amount = rewards.get(&key);

                let output = format!(
                  "0x{}{}{} => {} => {}",
                  hex::encode(&caller),
                  hex::encode(&salt),
                  hex::encode(&solution),
                  checksum_address,
                  reward_amount
                );

                let show = format!("{} ({} / {})", &output, &leading, &total);
                let next_found = vec![show.to_string()];
                found_list.extend(next_found);

                file.lock_exclusive().expect("Couldn't lock file.");

                writeln!(&file, "{}", &output).expect(
                  "Couldn't write to `efficient_addresses.txt` file."
                );

                file.unlock().expect("Couldn't unlock file.");
                found = found + 1;
            }
        });
    }
}

/// Remove the `0x` prefix from a hex string.
fn without_prefix(string: String) -> String {
    string
      .char_indices()
      .nth(2)
      .and_then(|(i, _)| string.get(i..))
      .unwrap()
      .to_string()
}

/// Convert a properly-sized vector to a fixed array of 20 bytes.
fn to_fixed_20(bytes: std::vec::Vec<u8>) -> [u8; 20] {
    let mut array = [0; 20];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

/// Convert a properly-sized vector to a fixed array of 32 bytes.
fn to_fixed_32(bytes: std::vec::Vec<u8>) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

/// Convert a properly-sized vector to a fixed array of 47 bytes.
fn to_fixed_47(bytes: &std::vec::Vec<u8>) -> [u8; 47] {
    let mut array = [0; 47];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

/// Convert a properly-sized vector to a fixed array of 4 bytes.
fn to_fixed_4(bytes: &std::vec::Vec<u8>) -> [u8; 4] {
    let mut array = [0; 4];
    let bytes = &bytes[..array.len()];
    array.copy_from_slice(bytes);
    array
}

/// Convert a 64-bit unsigned integer to a fixed array of six bytes.
fn u64_to_fixed_6(x: &u64) -> [u8; 6] {
    let mask: u64 = 0xff;
    let b1: u8 = ((x >> 40) & mask) as u8;
    let b2: u8 = ((x >> 32) & mask) as u8;
    let b3: u8 = ((x >> 24) & mask) as u8;
    let b4: u8 = ((x >> 16) & mask) as u8;
    let b5: u8 = ((x >> 8) & mask) as u8;
    let b6: u8 = (x & mask) as u8;
    [b1, b2, b3, b4, b5, b6]
}

/// Convert 64-bit unsigned integer to little-endian fixed array of eight bytes.
fn u64_to_le_fixed_8(x: &u64) -> [u8; 8] {
    let mask: u64 = 0xff;
    let b1: u8 = ((x >> 56) & mask) as u8;
    let b2: u8 = ((x >> 48) & mask) as u8;
    let b3: u8 = ((x >> 40) & mask) as u8;
    let b4: u8 = ((x >> 32) & mask) as u8;
    let b5: u8 = ((x >> 24) & mask) as u8;
    let b6: u8 = ((x >> 16) & mask) as u8;
    let b7: u8 = ((x >> 8) & mask) as u8;
    let b8: u8 = (x & mask) as u8;
    [b8, b7, b6, b5, b4, b3, b2, b1]
}
