// Author : Axel Vallon
// Date : 02.05.2022
use crate::crypto::{self, AsymetricEncryption};
use crate::crypto::{authentify_content, SymetricEncryption};
use crate::files_manager;

pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    /**
     * Login a user. 
     * Return : None if failed, Some(symetric_key) otherwise 
     */
    pub fn login(&self) -> Option<Vec<u8>> {
        if let Some(password_file) = files_manager::PasswordFile::get(&self.username) {
            if crypto::verify_hash_argon2(password_file.master_key_hash.clone(), &self.password)
            {
                // user has the correct passphrase
                let sym_key = crypto::get_sym_key(&self.password, &password_file.symetric_key_salt);
                // verification of file authenticity
                if password_file.mac.as_slice() == authentify_content( &sym_key, password_file.format_elements_to_hash()).as_slice()
                {
                    return Some(sym_key);
                }
            }
        }
        None
    }

    /**
     * Register a new user
     * Generate all needed paramter for a new user 
     *  - Hash of password
     *  - Symetric key
     *  - Salt of symetric key
     *  - RSA key pair (with encrypted private key)
     */
    pub fn register(&self) -> bool {
        // user already exist, we leave early.
        if files_manager::PasswordFile::get(&self.username).is_some() {
            return false;
        }
        // user data generation
        let hash = crypto::hash_password_argon2id(&self.password);
        let symetric_key = crypto::generate_sym_key(&self.password);
        let rsa_keys = AsymetricEncryption::generate_keys();
        match SymetricEncryption::encrypt(&symetric_key.sym_key, &rsa_keys.encode_private_key()) {
            Ok(encrypted_private_key) => {
                let mut fm = files_manager::PasswordFile::new(
                    self.username.clone(),
                    rsa_keys.encode_public_key(),
                    encrypted_private_key.ciphertext,
                    encrypted_private_key.nonce,
                    hash.as_bytes().to_vec(),
                    symetric_key.salt,
                );
                // save the new user in a new file.
                return fm.save_and_mac(&symetric_key.sym_key).is_ok();
            }
            Err(_) => return false, // rsa private key encryption failed.
        }
    }

    pub fn new(username: String, password: String) -> Credentials {
        Credentials { username, password }
    }
}
