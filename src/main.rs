mod age;

use crate::age::AgeCrypto;

const VERSION: &str = "0.0.1";

// Command Line Usage
const USAGE_STR: &str = "
tirrage Command Line.

Usage:

$ tirra COMMAND [ARGUMENTS]

tirrage  ver
tirrage  decrypt  IN_FILE OUT_FILE
tirrage  encrypt  IN_FILE OUT_FILE 


COMMANDS
       ver    Display the version information and exit.
       decrypt
              Decrypt a file that was encrypted using Age v1/scrypt recipient type.
       encrypt
              Encrypt a plaintext file using Age v1/scrypt recipient type.

ARGUMENTS
       IN_FILE & OUT_FILE
              input and output file paths
";

#[derive(PartialEq)]
enum CliAction {
    Decrypt,
    Encrypt,
    Version,
}

pub fn process(args: &Vec<String>, args_count: usize) {
    let cli_action: CliAction;

    if args_count == 1 {
        println!("{}", USAGE_STR);
        return;
    }

    match args[1].as_str() {
        "decrypt" => cli_action = CliAction::Decrypt,
        "encrypt" => cli_action = CliAction::Encrypt,
        "ver" => cli_action = CliAction::Version,
        _ => {
            println!("{}", USAGE_STR);
            return;
        }
    }

    if cli_action == CliAction::Version {
        println!("tirrage v{}", VERSION);
    } else if cli_action == CliAction::Decrypt {
        if args_count != 4 {
            println!("{}", USAGE_STR);
            return;
        }

        let db_path = String::from(&args[2]);
        let out_path = String::from(&args[3]);

        // Get Password
        let password: String = ask_for_pwd();
        let pwd = password.as_bytes();

        match decrypt_file(&db_path, &out_path, &pwd) {
            Ok(_) => {
                println!("file successfully decrypted");
            }
            Err(_) => {
                println!("failed to decrypt file {}", &db_path);
            }
        }
    } else if cli_action == CliAction::Encrypt {
        if args_count != 4 {
            println!("{}", USAGE_STR);
            return;
        }

        let clear_path = String::from(&args[2]);
        let out_path = String::from(&args[3]);

        // Get Password
        let password: String = ask_for_pwd();
        let pwd = password.as_bytes();

        match encrypt_file(&clear_path, &out_path, &pwd) {
            Ok(_) => {
                println!("file successfully encrypted");
            }
            Err(_) => {
                println!("failed to encrypt file {}", clear_path);
            }
        }
    }
}

fn ask_for_pwd() -> String {
    // ask for password
    let password = rpassword::prompt_password("password: ").unwrap();
    password
}

/**
 * Encrypted a file with a passphrase
 */
fn encrypt_file(plain_file: &str, encrypted_file: &str, password: &[u8]) -> Result<bool, ()> {
    let age = AgeCrypto::from_password(password).map_err(|_| ())?;
    age.encrypt_with(plain_file, encrypted_file)
        .map_err(|_| ())?;

    Ok(true)
}

/**
 * decrypt a file with a passphrase
 */
fn decrypt_file(encrypted_file: &str, plain_file: &str, password: &[u8]) -> Result<bool, ()> {
    let mut age = AgeCrypto::from_secrets(encrypted_file, password).map_err(|_| ())?;

    age.decrypt_with(plain_file).map_err(|_| ())?;

    Ok(true)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let args_count = args.len();
    process(&args, args_count);
}
