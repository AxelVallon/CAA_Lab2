// Author : Axel Vallon
// Date : 02.05.2022
use files_manager::Password;
use read_input::{prelude::input, InputBuild, InputConstraints};
use utils::*;

mod authentification;
mod crypto;
mod files_manager;
mod utils;
use crate::authentification::Credentials;
use crate::crypto::{AsymetricEncryption, SymetricEncryption};
use colorful::Color;
use colorful::Colorful;

/**
 * Function to recover a password
 * Retrieve 2 types of password.
 *  -> Local password retrieved from local file
 *  -> Shared password. retrieve from local file and the public key of the user that shared it. (Another file atm)
 *  -> If two shared password has the same label, the user can select which one to read.
 * Result : Print the password and copy it in the clipboard (Verified on Windows, but schould be ok elsewhere, see the crate copypasta)
 */
fn recover_handler(account: &String, sym_key: &Vec<u8>) {
    println!(
        "{}",
        "\nThis option allow to display a shared or an owned password\n".color(Color::Cyan)
    );
    print_username(&account);
    let label_input = input::<String>()
        .msg("Please enter the password label : ")
        .get();
    println!();
    // open local file and verification of it's authenticity. 
    match files_manager::PasswordFile::get_and_verify(&account, &sym_key) {
        Some(password_file) => match recover_password(&label_input, sym_key, &password_file) {
            Ok(clear_password) => match clear_password {
                Some(clear_password) => {
                    // password in local found and is valid
                    let password = std::str::from_utf8(clear_password.as_slice()).unwrap();
                    copy_to_clipboard(&password.to_string());
                    println!(
                        "{}{}{}",
                        "Password found : ".color(Color::Green),
                        password,
                        "\nPassword copied in clipboard".color(Color::Cyan)
                    )
                }
                None => {
                    // otherwhise, check if it is a shared password
                    let iterator = password_file
                        .shared_passwords
                        .keys()
                        .filter(|k| k.label == label_input)
                        .clone();
                    if iterator.clone().count() == 0 {
                        println!("{}", "Operation failed. The password you want to read don't exist in your file, not was shared by someone".color(Color::Orange1));
                    // one shared password has this label
                    } else if iterator.clone().count() == 1 {
                        let shared_password =
                            iterator.clone().find(|k| k.label == label_input).unwrap();
                        recover_asym_password(
                            sym_key,
                            &password_file,
                            &shared_password.owner,
                            shared_password,
                        );
                    // multiple shared password has this label. The user select one. loop while username not valid.
                    } else {
                        loop {
                            println!("Multiple user shared with you a password with this label");
                            for shared_password in iterator.clone() {
                                println!("{}", shared_password.owner);
                            }
                            print_username(&account);
                            let username_input = input::<String>()
                                .msg("Please enter the password label you want to read : ")
                                .get();
                            if let Some(shared_password) =
                                iterator.clone().find(|k| k.owner == username_input)
                            {   
                                recover_asym_password(
                                    sym_key,
                                    &password_file,
                                    &shared_password.owner,
                                    shared_password,
                                );
                                break;
                            }
                        }
                    }
                }
            },
            Err(_) => print_corrupted_local_file(),
        },
        None => print_corrupted_local_file(),
    }
}

/**
 * Function that ask a new password to the user, and save it.
 * Warning : Expand password input in 128 bytes, to have the same encrypted passwords size with all passwords.
 * If the password already exist, the content is uploaded.
 */
fn add_handler(account: &String, sym_key: &Vec<u8>) {
    println!(
        "{}",
        "\nThis option allow to add a password\n".color(Color::Cyan)
    );
    print_username(&account);
    let label_input = input::<String>()
        .msg("Please enter the password label : ")
        .get();
    if !label_verification(&label_input) {
        return;
    }
    print_username(&account);
    let password_input = input::<String>().msg("Please enter the password : ").get();
    if !password_verification(&password_input) {
        return;
    }
    println!();
    let mut password: Vec<u8> = password_input.as_bytes().to_vec();
    // DO NOT REMOVE THIS : Allow to store all passwords with the same size. 
    password.resize(128, 0u8);
    // open local file and verification of it's authenticity. 
    match files_manager::PasswordFile::get_and_verify(&account, &sym_key) {
        Some(mut password_file) => {
            // encrypt the extended password.
            let encrypted_password = SymetricEncryption::encrypt(&sym_key, &password).unwrap();
            password_file.passwords.insert(
                label_input,
                Password {
                    nonce: encrypted_password.nonce,
                    encrypted_password: encrypted_password.ciphertext,
                },
            );
            // save the new password.
            if password_file.save_and_mac(&sym_key).is_ok() {
                println!("{}", "Password saved".color(Color::Green))
            } else {
                print_failed_to_save_local_file();
            }
        }
        None => print_corrupted_local_file(),
    }
}

/**
 * Change the master password
 * Change the following user datas
 * - Create new password Hash
 * - Create new symetric key
 * - Update the private RSA key with the new symetric key
 * - Update all the passwords with the new symetric key
 * Return true if the update is successful.
 */
fn change_handler(account: &String, sym_key: &Vec<u8>) -> bool {
    println!(
        "{}",
        "\nThis option allow you to change your password\n".color(Color::Cyan)
    );
    print_username(&account);
    let password_input = input::<String>()
        .msg("Please enter your new password : ")
        .get();
    if !password_verification(&password_input) {
        return false;
    }
    println!();
    let new_hash = crypto::hash_password_argon2id(&password_input);
    let new_key = crypto::generate_sym_key(&password_input);
    match files_manager::PasswordFile::get_and_verify(&account, &sym_key) {
        Some(mut password_file) => {
            // Decryption and encryption of the RSA private key
            match decrypt_and_encrypt(
                sym_key,
                &new_key.sym_key,
                &password_file.encrypted_private_key,
                &password_file.encrypted_private_key_nonce,
            ) {
                Some(new_private_key_encrypted) => {
                    // iterate all local passwords. Decrypt and encrypt these password.
                    for password_to_update in password_file.passwords.values_mut() {
                        match decrypt_and_encrypt(
                            sym_key,
                            &new_key.sym_key,
                            &password_to_update.encrypted_password,
                            &password_to_update.nonce,
                        ) {
                            Some(new_password) => {
                                password_to_update.encrypted_password = new_password.ciphertext;
                                password_to_update.nonce = new_password.nonce;
                            }
                            None => {
                                print_corrupted_local_file();
                                return false; // Early return. We can't modify the master password if one of the password is corrupted
                            }
                        }
                    }
                    // Update the user data
                    password_file.encrypted_private_key = new_private_key_encrypted.ciphertext;
                    password_file.encrypted_private_key_nonce = new_private_key_encrypted.nonce;
                    password_file.master_key_hash = new_hash.as_bytes().to_vec();
                    password_file.symetric_key_salt = new_key.salt;
                    if password_file.save_and_mac(&new_key.sym_key).is_ok() {
                        println!(
                            "{}",
                            "Success ! Password modification successful".color(Color::Green)
                        );
                        return true;
                    } else {
                        print_failed_to_save_local_file()
                    }
                }
                // RSA private key corrupted
                None => print_corrupted_local_file(),
            }
        }
        None => print_corrupted_local_file(),
    }
    false
}

/**
 * Share a private password. option 4 of login
 *
 */
fn share_handler(account: &String, sym_key: &Vec<u8>) {
    println!();
    println!(
        "{}",
        "\nThis option allow you to share a password\n".color(Color::Cyan)
    );
    print_username(&account);
    let label_input = input::<String>()
        .msg("Please enter the password label to share : ")
        .get();
    if !label_verification(&label_input) {
        return;
    }
    print_username(&account);
    let username_input = input::<String>()
        .msg("Please enter the username you want to share with : ")
        .get();
    if !username_verification(&username_input) {
        return;
    }
    if account.clone() == username_input {
        println!(
            "{}",
            "Operation failed. You can't share a password with yourself".color(Color::Red)
        );
        return; //early return
    }

    println!();
    match files_manager::PasswordFile::get_and_verify(&account, &sym_key) {
        // the local file is valid
        Some(local_account) => {
            match files_manager::PasswordFile::get(&username_input) {
                // the distant file is valid. We write the share password in this file.
                Some(mut distant_file) => {
                    match recover_password(&label_input, sym_key, &local_account) {
                        // we retrieve the encrypted password we want to share from local file.
                        Ok(clear_password) => {
                            match clear_password {
                                Some(clear_password) => {
                                    let symetric_encryption = SymetricEncryption::new(
                                        local_account.encrypted_private_key,
                                        local_account.encrypted_private_key_nonce,
                                    );
                                    // we retrieve the encrypted the local user private key, and decrypt it
                                    match symetric_encryption.decrypt(sym_key) {
                                        Some(clear_private_key) => {
                                            // Encryption with local private key and sign with distant public key
                                            let parameters = AsymetricEncryption::new(
                                                &clear_private_key,
                                                &distant_file.public_key,
                                            );
                                            match parameters.encrypt(clear_password.as_slice()) {
                                                Ok(shared_password) => {
                                                    distant_file.shared_passwords.insert(files_manager::SharedPasswordIdentificatior{ owner: account.clone(), label: label_input }, shared_password );
                                                    if distant_file.save().is_ok() {
                                                        println!("{}", "Success ! Password shared".color(Color::Green));
                                                    } else {
                                                        println!("{}", "Operation failed. We were unable to update the distant file".color(Color::Orange1));
                                                    }
                                                }
                                                Err(_) => println!("{}","Critical error !\n The file of the person you want to share a password with has his file corrupted".color(Color::Red)),
                                            }
                                        }
                                        // RSA private key is corrupted
                                        None => print_corrupted_local_file(),
                                    }
                                }
                                None => print_password_to_share_dont_exist(),
                            }
                        }
                        // private key corrupted
                        Err(_) => print_corrupted_local_file(),
                    }
                }
                None => print_distant_user_dont_exist(),
            }
        }
        // file mac failed
        None => print_corrupted_local_file(),
    }
}

/**
 * Register handler
 * Ask credentials and create a user file (contains all the user's data)
 * The user is not connected at the end of this processus.
 */
fn register_handler() {
    let account_name_input = input::<String>()
        .msg("Please enter your account name    : ")
        .get();
    if !username_verification(&account_name_input) {
        return;
    }

    let password_input = input::<String>()
        .msg("Please enter your master password : ")
        .get();
    if !password_verification(&password_input) {
        return;
    }
    // RSA key generation take a good amount of time.
    println!("{}", "This may take some time".color(Color::Cyan));
    let cred = Credentials::new(account_name_input, password_input);
    if cred.register() {
        println!("{}", "Success ! Account created".color(Color::Green));
    } else {
        println!("{}", "Account creation failed".color(Color::Orange1));
    }
}

/**
 * Login handler
 * Ask credential and if the connection is successful, the user could ask to
 *  - Read a password (shared by someone or private one)
 *  - Add a password
 *  - Change the main password. The user would be disconnected if the password change is successful.
 *  - share one password
 */
fn login_handler() {
    let account_name_input = input::<String>()
        .msg("Please enter your account name    : ")
        .get();
    if !username_verification(&account_name_input) {
        return;
    }
    let password_input = input::<String>()
        .msg("Please enter your master password : ")
        .get();
    if !password_verification(&password_input) {
        return;
    }
    println!();
    // clear password not in the memory anymore after verification
    let cred = Credentials::new(account_name_input.clone(), password_input); 
    match cred.login() {
        Some(sym_key) => {
            println!("{}", "Login successful".color(Color::Green));
            println!(
                "{}",
                "---------------------------------------------------"
                    .color(Color::DarkGray)
                    .bold()
            );
            loop {
                print_username(&account_name_input);
                println!("Please select one of the following option : ");
                match input::<i32>()
                        .repeat_msg("0: Disconnect\n1: Recover password\n2: Add password\n3: Change master password\n4: Share password\nWhat do you want to do ? [0-4]")
                        .min_max(0, 4)
                        .get()
                    {
                        0 => {
                            println!("Disconnected");
                            break;
                        }
                        1 => recover_handler(&account_name_input, &sym_key),
                        2 => add_handler(&account_name_input, &sym_key),
                        // if the password change is succesful, the user is disconnected.
                        3 => if change_handler(&account_name_input, &sym_key){
                            break;
                        },
                        4 => share_handler(&account_name_input, &sym_key),
                        _ => panic!("Invalid input"),
                    }
                println!(
                    "{}",
                    "---------------------------------------------------"
                        .color(Color::DarkGray)
                        .bold()
                );
            }
        }
        None => println!("{}", "Login failed".color(Color::Orange1)),
    }
}

fn main() {
    // clear the shell
    print!("{}[2J", 27 as char);
    // header printing
    println!("{}","o-------------------------------------------------o".color(Color::DarkGray).bold());
    println!("{}","|             Basic password manager              |".color(Color::DarkGray).bold());
    println!("{}","|  Save, recover and share your password securly  |".color(Color::DarkGray).bold());
    println!("{}","o-------------------------------------------------o".color(Color::DarkGray).bold()
    );
    loop {
        println!("Please select one of the following option : ");
        match input::<i32>()
            .repeat_msg("0: Quit\n1: Register\n2: Login\nWhat do you want to do ? [0-2]")
            .min_max(0, 2)
            .get()
        {
            0 => {
                println!("Goodbye!");
                break;
            }
            1 => register_handler(),
            2 => login_handler(),
            _ => panic!("Invalid input"),
        }
        println!(
            "{}",
            "---------------------------------------------------"
                .color(Color::DarkGray)
                .bold()
        );
    }
}
