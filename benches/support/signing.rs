#![allow(dead_code)]

use ed25519_dalek::pkcs8::EncodePrivateKey;
use pkcs8::LineEnding;

#[cfg(feature = "encrypted-keys")]
use pkcs8::PrivateKeyInfo;

#[cfg(feature = "encrypted-keys")]
pub const PASSWORD: &[u8] = b"benchmark password";

pub fn unencrypted_pem() -> String {
    ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

#[cfg(feature = "encrypted-keys")]
pub fn encrypted_pem() -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let der = key.to_pkcs8_der().unwrap();
    let private_key = PrivateKeyInfo::try_from(der.as_bytes()).unwrap();
    let parameters =
        pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(2_048, &[3; 16], &[4; 16])
            .unwrap();
    private_key
        .encrypt_with_params(parameters, PASSWORD)
        .unwrap()
        .to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF)
        .unwrap()
        .to_string()
}
