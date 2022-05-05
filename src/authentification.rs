use crate::crypto::SymetricEncryption;
use crate::crypto::{self, AsymetricEncryption};
use crate::files_manager;

pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn login(&self) -> Option<Vec<u8>> {
        //TODO verify MAC
        // if file doesn't exist, this user doesn't exist. No leak.
        match files_manager::PasswordFile::get(&self.username) {
            Some(password_file) => {
                if crypto::verify_hash_argon2(password_file.master_key_hash, &self.password) {
                    return Some(crypto::get_sym_key(
                        &self.password,
                        &password_file.symetric_key_salt,
                    ));
                } else {
                    return None;
                }
            }
            None => return None,
        }
    }

    pub fn register(&self) -> bool {
        // user already exist, we leave early.
        if files_manager::PasswordFile::get(&self.username).is_some() {
            return false;
        }
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
                fm.mac = crypto::authentify_content(
                    &symetric_key.sym_key,
                    &fm.format_elements_to_hash(),
                )
                .to_vec();
                return fm.save().is_ok();
            }
            Err(_) => return false, // rsa private key encrpytion failed.
        }
    }
    pub fn new(username: String, password: String) -> Credentials {
        Credentials { username, password }
    }
}
