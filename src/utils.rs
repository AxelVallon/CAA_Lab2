use colorful::{Colorful, Color};
use regex::Regex;
extern crate copypasta;

use crate::{crypto::{AsymetricEncryption, SymetricEncryption}, files_manager::{self, PasswordFile, SharedPasswordIdentificatior}};
use copypasta::{ClipboardContext, ClipboardProvider};

pub fn copy_to_clipboard(message: &String){
    let mut ctx = ClipboardContext::new().unwrap();
    ctx.set_contents(message.clone()).unwrap();
}

pub fn label_verification(label : &String) -> bool{
    let re = Regex::new(r"[ -~]{1,128}").unwrap();
    let result = re.is_match(label);
    if !result {
        println!("{}", "The password label must have 1 to 128 characters".color(Color::Orange1));
    }
    result
}

// we only accept 1 to 64 character and <= 128 byte to be sure all passwords have the same lenght
pub fn password_verification(password : &String) -> bool{
    let re = Regex::new(r"^[ -~]{1,64}$").unwrap();
    let result = re.is_match(password) && password.len() <= 128;
    if !result {
        println!("{}", "The password must have 1 to 64 characters and be less than 128 bytes".color(Color::Orange1));
    }
    result
}


pub fn username_verification(username : &String) -> bool{
    let re = Regex::new(r"^[a-zA-Z0-9]{1,32}$").unwrap();
    let result = re.is_match(username);
    if !result {
        println!("{}", "The username must have 1 to 32 alphanumeric characters".color(Color::Orange1));
    }
    result
}


pub fn print_failed_to_save_local_file(){
    println!("{}","Operation failed. The localfile can not be override at the moment.".color(Color::Orange1));
}

pub fn print_password_to_share_dont_exist(){
    println!("{}","Operation failed. The password you want to share don't exist.".color(Color::Orange1));
}

pub fn print_distant_user_dont_exist() {
    println!("{}","Operation failed. You want to share a password with a non-existant user\nIf this user exist, it means his file is corrupted.".color(Color::Orange1));
}

pub fn print_corrupted_local_file() {
    println!("{}","Critical error !\n The file storing your data is corrupted or unreadable at the moment. You have three options :\n - Check if your file is opened elsewhere\n - Recover an old backup to ./data/your_username.json\n - Create a new account and your saved passwords are lost".color(Color::Red));
}

pub fn print_username(account : &String){
    print!("{}{}", account.as_str().color(Color::Cyan), " > ".color(Color::Cyan));
}

pub fn decrypt_and_encrypt(
    old_sym_key: &[u8],
    new_sym_key: &[u8],
    old_content: &[u8],
    old_nonce: &[u8],
) -> Option<SymetricEncryption> {
    let symetric_entryption = SymetricEncryption::new(old_content.to_vec(), old_nonce.to_vec());
    let cleartext = symetric_entryption.decrypt(old_sym_key)?;
    match SymetricEncryption::encrypt(new_sym_key, &cleartext) {
        Ok(new_symetric_entryption) => return Some(new_symetric_entryption),
        Err(_) => None,
    }
}

pub fn recover_password(
    label_input: &String,
    sym_key: &Vec<u8>,
    password_file: &files_manager::PasswordFile,
) -> Result<Option<Vec<u8>>, &'static str> {
    match password_file.passwords.get(label_input) {
        Some(password) => {
            match SymetricEncryption::new(
                password.encrypted_password.clone(),
                password.nonce.clone(),
            )
            .decrypt(&sym_key)
            {
                Some(clear_password) => {
                    return Ok(Some(clear_password));
                }
                None => return Err("This password is corrupted."),
            }
        }
        None => return Ok(None),
    }
}

pub fn recover_asym_password(
    sym_key: &Vec<u8>,
    password_file: &PasswordFile,
    distant_account: &String,
    shared_password: &SharedPasswordIdentificatior,
) {
    let password = password_file.shared_passwords.get(shared_password).unwrap();
    match files_manager::PasswordFile::get(&distant_account) {
        Some(distant_file) => {
            let parameters = SymetricEncryption::new(
                password_file.encrypted_private_key.clone(),
                password_file.encrypted_private_key_nonce.clone(),
            );
            match parameters.decrypt(&sym_key) {
                Some(clear_private_key) => {
                    let parameters =
                        AsymetricEncryption::new(&clear_private_key, &distant_file.public_key);
                    match parameters
                        .decrypt(&password.encrypted_password, &password.signature)
                    {
                        Ok(clear_password) => {
                            let password = std::str::from_utf8(clear_password.as_slice()).unwrap();
                            copy_to_clipboard(&password.to_string());
                            println!("{}{}", "Password found : ".color(Color::Green), password);
                            println!("{}{}", "Password shared by ".color(Color::Cyan), distant_account.as_str().color(Color::Cyan));
                        },
                        Err(_) => println!("{}","Critical error !\n The file of the password that shared this password with you has his file corrupted".color(Color::Red)),
                    }
                }
                None => print_corrupted_local_file(),
            }
        }
        None => println!("{}",
            "Operation failed. The user that shared with you this password don't exist anymore.".color(Color::Orange1)
        ),
    }
}