// Author : Axel Vallon
// Date : 02.05.2022
// Serialize, deserialize, load and save user datas in a File

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs::OpenOptions, io::Write};

use crate::crypto::authentify_content;

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordFile {
    owner: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub encrypted_private_key_nonce: Vec<u8>,
    pub symetric_key_salt: Vec<u8>,
    pub master_key_hash: Vec<u8>,
    pub mac: Vec<u8>,
    pub passwords: HashMap<String, Password>,
    #[serde(with = "vectorize")]
    pub shared_passwords: HashMap<SharedPasswordIdentificatior, SharedPassword>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    pub encrypted_password: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SharedPassword {
    pub encrypted_password: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Hash)]
pub struct SharedPasswordIdentificatior {
    pub owner: String,
    pub label: String,
}

impl PartialEq for SharedPasswordIdentificatior {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner && self.label == other.label
    }
}

impl Eq for SharedPasswordIdentificatior {}

impl PasswordFile {
    pub fn new(
        owner: String,
        public_key: Vec<u8>,
        encrypted_private_key: Vec<u8>,
        encrypted_private_key_nonce: Vec<u8>,
        master_key_hash: Vec<u8>,
        symetric_key_salt: Vec<u8>,
    ) -> PasswordFile {
        let passwords = HashMap::new();
        let shared_passwords = HashMap::new();
        let mac = Vec::new();
        PasswordFile {
            owner,
            public_key,
            encrypted_private_key,
            encrypted_private_key_nonce,
            master_key_hash,
            symetric_key_salt,
            mac,
            passwords,
            shared_passwords,
        }
    }

    pub fn format_elements_to_hash(&self) -> String {
        return self.owner.clone()
            + &format!("{:?}", &self.public_key)
            + &format!("{:?}", &self.master_key_hash)
            + &format!("{:?}", &self.symetric_key_salt);
    }

    // get the Content of the File in the PasswordFile struct.
    pub fn get(owner: &String) -> Option<PasswordFile> {
        const PATH_TO_DATABASE: &str = "data/";
        let buffer = std::fs::read(PATH_TO_DATABASE.to_string() + &owner + ".json");
        if let Ok(file_content) = buffer {
            if let Ok(password_file) = serde_json::from_slice(&file_content) {
                return Some(password_file);
            }
        }
        None
    }

    /**
     * Get a file and verify if the file is authentic with a MAC
     */
    pub fn get_and_verify(owner: &String, sym_key: &Vec<u8>) -> Option<PasswordFile> {
        let password_file = Self::get(owner)?;
        if password_file.mac
            == authentify_content(sym_key, password_file.format_elements_to_hash()).as_slice()
        {
            Some(password_file)
        } else {
            None
        }
    }

    /**
     * Save the user data and update the MAC.
     */
    pub fn save(&mut self) -> std::io::Result<()> {
        const PATH_TO_DATABASE: &str = "data/";
        // open the file, if non existant, create it, if existant, override.
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(PATH_TO_DATABASE.to_string() + &self.owner + ".json")?;
        // write user data nicely
        serde_json::to_writer_pretty(&mut file, &self)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    }

    pub fn save_and_mac(&mut self, sym_key: &Vec<u8>)  -> std::io::Result<()>  {
        self.mac = authentify_content(sym_key, self.format_elements_to_hash()).as_slice().to_vec();
        self.save()
    }

}
#[cfg(test)]
mod tests {
    use super::PasswordFile;

    #[test]
    fn functionnement_test() {
        let mut password_file = PasswordFile::new(
            "owner_that_schould_not_exist[".to_string(),
            "public_key".as_bytes().to_vec(),
            "encrypted_private_key".as_bytes().to_vec(),
            "master_key_salt".as_bytes().to_vec(),
            "master_key_hash".as_bytes().to_vec(),
            "symetric_key_salut".as_bytes().to_vec(),
        );
        assert!(password_file.save().is_ok());
        assert!(
            password_file.owner
                == PasswordFile::get(&"owner_that_schould_not_exist[".to_string())
                    .unwrap()
                    .owner
        );
        std::fs::remove_file("data/owner_that_schould_not_exist[").ok();
    }
}
