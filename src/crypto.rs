use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use argon2::{self, hash_encoded, Config};
use hmac::digest::Output;
use hmac::{Hmac, Mac};
use rand::{self, Rng, RngCore};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::files_manager;

pub fn hash_password_argon2id(password: &String) -> String {
    let salt = rand::rngs::OsRng.gen::<[u8; 16]>(); //16 * 8 = 128 bit as recommended by the author of Argon2
    let mut config = Config::default(); // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.4
    config.variant = argon2::Variant::Argon2id;
    hash_encoded(password.as_bytes(), &salt, &config).unwrap()
}

pub fn verify_hash_argon2(hash: Vec<u8>, password: &String) -> bool {
    argon2::verify_encoded(std::str::from_utf8(&hash).unwrap(), password.as_bytes()).unwrap()
}

// ***************** SYMETRIC KEY ********************** //

pub struct SymKey {
    pub salt: Vec<u8>,
    pub sym_key: Vec<u8>,
}

pub fn generate_sym_key(password: &String) -> SymKey {
    let salt = rand::rngs::OsRng.gen::<[u8; 16]>(); //16 * 8 = 128 bit as recommended by the author of Argon2
    let mut config = Config::default(); // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.4
    config.variant = argon2::Variant::Argon2id;
    config.hash_length = 128;
    let hash = hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    let sym_key: Vec<u8> = hash.as_bytes()[hash.len() - 16..].to_vec();
    SymKey {
        salt: salt.to_vec(),
        sym_key,
    }
}

pub fn get_sym_key(password: &String, salt: &[u8]) -> Vec<u8> {
    let mut config = Config::default(); // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-argon2-03#section-9.4
    config.variant = argon2::Variant::Argon2id;
    config.hash_length = 128;
    let hash = hash_encoded(password.as_bytes(), &salt, &config).unwrap();
    hash.as_bytes()[hash.len() - 16..].to_vec()
}

// ***************** MAC ********************** //

pub fn authentify_content(key: &[u8], content: &String) -> Output<Hmac<Sha256>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(content.as_bytes());
    return mac.finalize().into_bytes();
}

// ***************** SYMETRIC CRYPTOGRAPHY ********************** //

pub struct SymetricEncryption {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
impl SymetricEncryption {
    pub fn encrypt(key: &[u8], message: &[u8]) -> Result<SymetricEncryption, aes_gcm::Error> {
        let key = Key::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let mut nonce_slice = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_slice[..]);
        let nonce = Nonce::from_slice(&nonce_slice); // 96 bit
        let ciphertext = cipher.encrypt(&nonce, message.as_ref())?; // tag is included in the result
        return Ok(SymetricEncryption {
            nonce: nonce_slice.to_vec(),
            ciphertext,
        });
    }

    pub fn decrypt(&self, key: &[u8]) -> Option<Vec<u8>> {
        let key = Key::from_slice(key);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce); // 96 bit
        match cipher.decrypt(nonce, self.ciphertext.as_ref()) {
            Ok(cleartext) => return Some(cleartext),
            Err(_) => {
                return None;
            }
        }
    }
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> SymetricEncryption {
        SymetricEncryption { ciphertext, nonce }
    }
}

// ***************** ASYMETRIC CRYPROTGRAPHY ********************** //

pub struct AsymetricEncryption {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl AsymetricEncryption {
    pub fn new(private_key: &[u8], public_key: &[u8]) -> Self {
        let public_key: rsa::RsaPublicKey =
            pkcs1::DecodeRsaPublicKey::from_pkcs1_der(public_key).unwrap();
        let private_key: rsa::RsaPrivateKey =
            pkcs1::DecodeRsaPrivateKey::from_pkcs1_der(private_key).unwrap();
        Self {
            private_key,
            public_key,
        }
    }

    pub fn encode_private_key(&self) -> Vec<u8> {
        pkcs1::EncodeRsaPrivateKey::to_pkcs1_der(&self.private_key)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        pkcs1::EncodeRsaPublicKey::to_pkcs1_der(&self.public_key)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    pub fn generate_keys() -> Self {
        let mut rng = rand::rngs::OsRng {};
        let bits = 2048; //TODO sure is enought but maybe 3000 would be ok
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn encrypt(
        &self,
        message: &[u8],
    ) -> Result<files_manager::SharedPassword, rsa::errors::Error> {
        let mut rng = rand::rngs::OsRng {};
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        let encrypted_password = self.public_key.encrypt(&mut rng, padding, message)?;
        let padding = rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rng);
        let mut hasher = Sha256::new();
        hasher.update(&encrypted_password);
        let result: &[u8] = &hasher.finalize();
        let signature = self.private_key.sign(padding, result)?;
        return Ok(files_manager::SharedPassword {
            encrypted_password,
            signature,
        });
    }

    pub fn decrypt(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<Vec<u8>, rsa::errors::Error> {
        let rng = rand::rngs::OsRng {};
        let padding = rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rng);
        let mut hasher = Sha256::new();
        hasher.update(message);
        let result: &[u8] = &hasher.finalize();
        self.public_key.verify(padding, result, signature)?;
        let padding = PaddingScheme::new_oaep::<Sha256>();
        self.private_key.decrypt(padding, message)
    }
}
