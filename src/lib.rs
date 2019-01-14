extern crate fs2;
extern crate hex;
extern crate rand;
extern crate rayon;
extern crate tiny_keccak;

use std::collections::HashMap;
use std::error::Error;
use std::i64;
use std::io::prelude::*;
use std::fs::OpenOptions;

use fs2::FileExt;
use hex::FromHex;
use rand::{thread_rng, Rng};
use rayon::prelude::*;
use tiny_keccak::Keccak;

/// Requires three hex-encoded arguments: the address of the contract that will
/// be calling CREATE2, the address of the caller of said contract *(assuming
/// the contract calling CREATE2 has frontrunning protection in place - if not
/// applicable to your use-case you can set it to the null address)*, and the
/// keccak-256 hash of the bytecode that is provided by the contract calling
/// CREATE2 that will be used to initialize the new contract.
pub struct Config {
    pub factory_address: [u8; 20],
    pub calling_address: [u8; 20],
    pub init_code_hash: [u8; 32],
}

/// Validate the three provided arguments and construct the Config struct.
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

        // convert arguments from hex string to vector of bytes
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

        // return the config object
        Ok(Self { factory_address, calling_address, init_code_hash })
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
pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    // (create if necessary) and open a file where found salts will be written
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("efficient_addresses.txt")
        .expect("Could not create or open `efficient_addresses.txt` file.");

    // initialize hash map for adress reward values given zero bytes
    let mut reward = HashMap::new();
    reward.insert(String::from("5"), String::from("4"));
    reward.insert(String::from("6"), String::from("454"));
    reward.insert(String::from("7"), String::from("57926"));
    reward.insert(String::from("8"), String::from("9100294"));
    reward.insert(String::from("9"), String::from("1742029446"));
    reward.insert(String::from("10"), String::from("404137334455"));
    reward.insert(String::from("11"), String::from("113431422629339"));
    reward.insert(String::from("12"), String::from("38587085346610622"));
    reward.insert(String::from("13"), String::from("15996770875963838293"));
    reward.insert(String::from("14"), String::from("8161556895428437076912"));
    reward.insert(String::from("15"), String::from("5204779792920449185083823"));
    reward.insert(String::from("16"), String::from("4248387252809145069797255323"));
    reward.insert(String::from("17"), String::from("4605429522902726696350853424531"));
    reward.insert(String::from("18"), String::from("7048004537575756103097351214228445"));
    reward.insert(String::from("19"), String::from("17077491850962604714099960694478075305"));
    reward.insert(String::from("25"), String::from("18"));
    reward.insert(String::from("26"), String::from("1510"));
    reward.insert(String::from("27"), String::from("165350"));
    reward.insert(String::from("28"), String::from("22735825"));
    reward.insert(String::from("29"), String::from("3869316742"));
    reward.insert(String::from("30"), String::from("807985948644"));
    reward.insert(String::from("31"), String::from("206183716874451"));
    reward.insert(String::from("32"), String::from("64298858504764852"));
    reward.insert(String::from("33"), String::from("24606700946514329477"));
    reward.insert(String::from("34"), String::from("11658059615639150243674"));
    reward.insert(String::from("35"), String::from("6939139116010292965409030"));
    reward.insert(String::from("36"), String::from("5310177709695884701197848448"));
    reward.insert(String::from("37"), String::from("5417944041740025730272641342830"));
    reward.insert(String::from("38"), String::from("7830936568539684766699669978646642"));
    reward.insert(String::from("39"), String::from("17976121735815156138387102662511898913"));
    reward.insert(String::from("44"), String::from("2"));
    reward.insert(String::from("45"), String::from("84"));
    reward.insert(String::from("46"), String::from("5728"));
    reward.insert(String::from("47"), String::from("522972"));
    reward.insert(String::from("48"), String::from("61659518"));
    reward.insert(String::from("49"), String::from("9184107994"));
    reward.insert(String::from("50"), String::from("1705003336895"));
    reward.insert(String::from("51"), String::from("391623153514096"));
    reward.insert(String::from("52"), String::from("111035232373186089"));
    reward.insert(String::from("53"), String::from("38953746656818437996"));
    reward.insert(String::from("54"), String::from("17036497937743417006573"));
    reward.insert(String::from("55"), String::from("9416523284246997364709332"));
    reward.insert(String::from("56"), String::from("6725785327750463676116311208"));
    reward.insert(String::from("57"), String::from("6433530232804950076993156196671"));
    reward.insert(String::from("58"), String::from("8751998904874491998186743074190073"));
    reward.insert(String::from("59"), String::from("18974577637063874242348921695171566572"));
    reward.insert(String::from("63"), String::from("1"));
    reward.insert(String::from("64"), String::from("16"));
    reward.insert(String::from("65"), String::from("501"));
    reward.insert(String::from("66"), String::from("25706"));
    reward.insert(String::from("67"), String::from("1879489"));
    reward.insert(String::from("68"), String::from("184770685"));
    reward.insert(String::from("69"), String::from("23598039458"));
    reward.insert(String::from("70"), String::from("3834163535637"));
    reward.insert(String::from("71"), String::from("782938604015677"));
    reward.insert(String::from("72"), String::from("199806334259175276"));
    reward.insert(String::from("73"), String::from("63729223611100778985"));
    reward.insert(String::from("74"), String::from("25550889257134282768770"));
    reward.insert(String::from("75"), String::from("13036857507600936595914846"));
    reward.insert(String::from("76"), String::from("8646792118767830540030515565"));
    reward.insert(String::from("77"), String::from("7719857784103882545156250250796"));
    reward.insert(String::from("78"), String::from("9845714873472744513017103980332671"));
    reward.insert(String::from("79"), String::from("20090471847730684189719534018111776322"));
    reward.insert(String::from("84"), String::from("256"));
    reward.insert(String::from("85"), String::from("4217"));
    reward.insert(String::from("86"), String::from("144997"));
    reward.insert(String::from("87"), String::from("7967408"));
    reward.insert(String::from("88"), String::from("627232017"));
    reward.insert(String::from("89"), String::from("66792260819"));
    reward.insert(String::from("90"), String::from("9305004719113"));
    reward.insert(String::from("91"), String::from("1662927453401532"));
    reward.insert(String::from("92"), String::from("377280206974005998"));
    reward.insert(String::from("93"), String::from("108312611697003383786"));
    reward.insert(String::from("94"), String::from("39480692955577390009145"));
    reward.insert(String::from("95"), String::from("18466558683234331672667696"));
    reward.insert(String::from("96"), String::from("11306368626474766596196174270"));
    reward.insert(String::from("97"), String::from("9373587789723760876051759069103"));
    reward.insert(String::from("98"), String::from("11158112222962749668746090824795165"));
    reward.insert(String::from("99"), String::from("21345818655172812214316074369647797631"));
    reward.insert(String::from("105"), String::from("65536"));
    reward.insert(String::from("106"), String::from("1149384"));
    reward.insert(String::from("107"), String::from("42311994"));
    reward.insert(String::from("108"), String::from("2503009344"));
    reward.insert(String::from("109"), String::from("213427112297"));
    reward.insert(String::from("110"), String::from("24790124569401"));
    reward.insert(String::from("111"), String::from("3798576841874147"));
    reward.insert(String::from("112"), String::from("754231113879134009"));
    reward.insert(String::from("113"), String::from("192496950430879408810"));
    reward.insert(String::from("114"), String::from("63155584261947917379593"));
    reward.insert(String::from("115"), String::from("26856456513120542636583476"));
    reward.insert(String::from("116"), String::from("15073641750015138940509892079"));
    reward.insert(String::from("117"), String::from("11535977580589283558152309456824"));
    reward.insert(String::from("118"), String::from("12751652018255015903154966566038849"));
    reward.insert(String::from("119"), String::from("22768501289012087466446392969820350793"));
    reward.insert(String::from("126"), String::from("16777216"));
    reward.insert(String::from("127"), String::from("314649014"));
    reward.insert(String::from("128"), String::from("12465892329"));
    reward.insert(String::from("129"), String::from("798621491520"));
    reward.insert(String::from("130"), String::from("74272940112557"));
    reward.insert(String::from("131"), String::from("9488446269991021"));
    reward.insert(String::from("132"), String::from("1615302625848366483"));
    reward.insert(String::from("133"), String::from("360793996621274970151"));
    reward.insert(String::from("134"), String::from("105231762185667073323510"));
    reward.insert(String::from("135"), String::from("40277499209379064589210374"));
    reward.insert(String::from("136"), String::from("20552522428100944971108965855"));
    reward.insert(String::from("137"), String::from("14418884344710441156786200615788"));
    reward.insert(String::from("138"), String::from("14712810623981817234669488026294327"));
    reward.insert(String::from("139"), String::from("24394367384979066549040576729916735405"));
    reward.insert(String::from("147"), String::from("4294967296"));
    reward.insert(String::from("148"), String::from("86578212486"));
    reward.insert(String::from("149"), String::from("3713485713636"));
    reward.insert(String::from("150"), String::from("259444579476332"));
    reward.insert(String::from("151"), String::from("26536334094930946"));
    reward.insert(String::from("152"), String::from("3766219523861070771"));
    reward.insert(String::from("153"), String::from("721233811714863908602"));
    reward.insert(String::from("154"), String::from("184095343314545289307447"));
    reward.insert(String::from("155"), String::from("62640228392039477591429356"));
    reward.insert(String::from("156"), String::from("28769426614997062585251169958"));
    reward.insert(String::from("157"), String::from("18349671535208654280022928803766"));
    reward.insert(String::from("158"), String::from("17164082814922458575890189696960250"));
    reward.insert(String::from("159"), String::from("26270291294258216720936037244430839003"));
    reward.insert(String::from("168"), String::from("1099511627776"));
    reward.insert(String::from("169"), String::from("23964464223668"));
    reward.insert(String::from("170"), String::from("1120582017742425"));
    reward.insert(String::from("171"), String::from("86090644707729148"));
    reward.insert(String::from("172"), String::from("9781914561024998962"));
    reward.insert(String::from("173"), String::from("1561650570729335220208"));
    reward.insert(String::from("174"), String::from("341747557162857934539820"));
    reward.insert(String::from("175"), String::from("101762631449317943805391008"));
    reward.insert(String::from("176"), String::from("41548592731868112513336784332"));
    reward.insert(String::from("177"), String::from("23852021372062826058224022750488"));
    reward.insert(String::from("178"), String::from("20283619999520397681386221215474723"));
    reward.insert(String::from("179"), String::from("28458767047291815304352793042317106218"));
    reward.insert(String::from("189"), String::from("281474976710656"));
    reward.insert(String::from("190"), String::from("6679635020504935"));
    reward.insert(String::from("191"), String::from("343348968927242275"));
    reward.insert(String::from("192"), String::from("29299651301902406699"));
    reward.insert(String::from("193"), String::from("3744527648085709786177"));
    reward.insert(String::from("194"), String::from("683111829267922829815475"));
    reward.insert(String::from("195"), String::from("174389101583031582235029592"));
    reward.insert(String::from("196"), String::from("62309305812704133847182785129"));
    reward.insert(String::from("197"), String::from("31798537455673449566787122847131"));
    reward.insert(String::from("198"), String::from("24338608729695493646905227621216324"));
    reward.insert(String::from("199"), String::from("31045005677747771435004953493418625136"));
    reward.insert(String::from("210"), String::from("72057594037927936"));
    reward.insert(String::from("211"), String::from("1877332990277416666"));
    reward.insert(String::from("212"), String::from("107151043349371744458"));
    reward.insert(String::from("213"), String::from("10283303505204142788147"));
    reward.insert(String::from("214"), String::from("1501666268767778355745184"));
    reward.insert(String::from("215"), String::from("319563996343164377392648004"));
    reward.insert(String::from("216"), String::from("97887186140032477917162659539"));
    reward.insert(String::from("217"), String::from("43715844026074104250142609225871"));
    reward.insert(String::from("218"), String::from("29744596511106126675202002373267873"));
    reward.insert(String::from("219"), String::from("34148289271564189198990160526277013772"));
    reward.insert(String::from("231"), String::from("18446744073709551616"));
    reward.insert(String::from("232"), String::from("532959419305417460751"));
    reward.insert(String::from("233"), String::from("34199245650990087306275"));
    reward.insert(String::from("234"), String::from("3749746141559948245944138"));
    reward.insert(String::from("235"), String::from("638710029020633448795855198"));
    reward.insert(String::from("236"), String::from("163084358451243040745529676767"));
    reward.insert(String::from("237"), String::from("62438084943177950193287569739764"));
    reward.insert(String::from("238"), String::from("37176696243831180424780470563509268"));
    reward.insert(String::from("239"), String::from("37940891085261431466299607797270323229"));
    reward.insert(String::from("252"), String::from("4722366482869645213696"));
    reward.insert(String::from("253"), String::from("153193891968249828851470"));
    reward.insert(String::from("254"), String::from("11227181263850205045367657"));
    reward.insert(String::from("255"), String::from("1435688191035029671162366337"));
    reward.insert(String::from("256"), String::from("293398319948847143266500005656"));
    reward.insert(String::from("257"), String::from("93630892949291171900768956557205"));
    reward.insert(String::from("258"), String::from("47791916641892757471645121003221337"));
    reward.insert(String::from("259"), String::from("42681178800470478513779470603886654646"));
    reward.insert(String::from("273"), String::from("1208925819614629174706176"));
    reward.insert(String::from("274"), String::from("44732959070623750795478391"));
    reward.insert(String::from("275"), String::from("3822247790422955620553331984"));
    reward.insert(String::from("276"), String::from("586336408451091794686883885323"));
    reward.insert(String::from("277"), String::from("149750686574114300529965478692459"));
    reward.insert(String::from("278"), String::from("63710659778031659693093889760656253"));
    reward.insert(String::from("279"), String::from("48775076109608200809979786955505409929"));
    reward.insert(String::from("294"), String::from("309485009821345068724781056"));
    reward.insert(String::from("295"), String::from("13334234657309393827615911462"));
    reward.insert(String::from("296"), String::from("1366330837671149190637746723640"));
    reward.insert(String::from("297"), String::from("261909596987600478890300387369290"));
    reward.insert(String::from("298"), String::from("89171615213500834928461796224542241"));
    reward.insert(String::from("299"), String::from("56898945742495262342667471915436095449"));
    reward.insert(String::from("315"), String::from("79228162514264337593543950336"));
    reward.insert(String::from("316"), String::from("4088297221333277495599464183220"));
    reward.insert(String::from("317"), String::from("523306049315415466265913015411891"));
    reward.insert(String::from("318"), String::from("133705003225903872825679864660094397"));
    reward.insert(String::from("319"), String::from("68269816560940632168200548199477007941"));
    reward.insert(String::from("336"), String::from("20282409603651670423947251286016"));
    reward.insert(String::from("337"), String::from("1305704925411524904272035688089603"));
    reward.insert(String::from("338"), String::from("222696176178091542181357768092554566"));
    reward.insert(String::from("339"), String::from("85320554291635892895811850639111324322"));
    reward.insert(String::from("357"), String::from("5192296858534827628530496329220096"));
    reward.insert(String::from("358"), String::from("444811280231209229153363695561872448"));
    reward.insert(String::from("359"), String::from("113723610876971601366349738253959088946"));
    reward.insert(String::from("378"), String::from("1329227995784915872903807060280344576"));
    reward.insert(String::from("379"), String::from("170474140766654103026661251472666657794"));
    reward.insert(String::from("399"), String::from("340282366920938463463374607431768211456"));
    reward.insert(String::from("420"), String::from("87112285931760246646623899502532662132736"));

    let zero_character: u8 = 0x00;
    let initial_control_character: Vec<u8> = vec![0xff];
    let default_value = String::from("0");
    let footer: [u8; 32] = config.init_code_hash;
    let max_incrementer: u64 = 281474976710655;

    loop {
        let mut rng = thread_rng();
        let salt_random_segment = rng.gen_iter::<u8>()
                                    .take(6)
                                    .collect::<Vec<u8>>();
     
        // header: 0xff ++ factory ++ caller ++ salt_random_segment (47 bytes)
        let mut header_vec: Vec<u8> = vec![];

        header_vec.extend(&initial_control_character);
        header_vec.extend(config.factory_address.iter());
        header_vec.extend(config.calling_address.iter());
        header_vec.extend(salt_random_segment);

        let header: [u8; 47] = to_fixed_47(&header_vec);

        (0..max_incrementer)
          .into_par_iter() // parallelization
          .map(|x| u64_to_fixed_6(&x)) // convert integer nonces to fixed arrays
          .for_each(|salt_incremented_segment| {
            // create new hash object
            let mut hash = Keccak::new_keccak256();

            // update with header, body, and footer (total: 85 bytes)
            hash.update(&header);
            hash.update(&salt_incremented_segment);
            hash.update(&footer);

            // hash the payload and get the result
            let mut res: [u8; 32] = [0; 32];
            hash.finalize(&mut res);

            // truncate the first 12 bytes from the hash to derive the address
            let mut address_bytes: [u8; 20] = Default::default();
            address_bytes.copy_from_slice(&res[12..]);

            // get the total zero bytes associated with the address
            let total = address_bytes
                          .iter()
                          .filter(|&n| *n == zero_character)
                          .count();

            if total > 2 {
                // get the leading zero bytes associated with the address
                let mut leading = 0;

                // iterate through each byte of address and count zero bytes
                for (i, b) in address_bytes.iter().enumerate() {
                  if b != &zero_character {
                    leading = i; // set leading value on reaching non-zero byte
                    break; // stop upon locating - unless it's the null address!
                  }
                }

                // look up the reward amount
                let key = (leading * 20 + total).to_string();
                let reward_amount = reward.get(&key).unwrap_or(&default_value);

                // proceed if an efficient address has been found
                if reward_amount != &default_value {
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

                    // display the salt and the address.
                    let output = format!(
                        "{} => {} => {}",
                        full_salt,
                        checksum_address,
                        reward_amount
                    );
                    println!("{}", &output);

                    file.lock_exclusive().expect("Couldn't lock file.");

                    writeln!(&file, "{}", &output).expect(
                        "Couldn't write to `efficient_addresses.txt` file."
                    );

                    file.unlock().expect("Couldn't unlock file.")
                }  
            }
        });
    }
}

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
