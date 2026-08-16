use ed25519_dalek::pkcs8::EncodePrivateKey;
use gungraun::{library_benchmark, library_benchmark_group, main};
use pkcs8::{LineEnding, PrivateKeyInfo};
use std::hint::black_box;
use treetop_bundle::SigningKey;

const PASSWORD: &[u8] = b"benchmark password";

fn unencrypted_pem() -> String {
    ed25519_dalek::SigningKey::from_bytes(&[42; 32])
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string()
}

fn encrypted_pem() -> String {
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

#[library_benchmark(setup = unencrypted_pem)]
fn load_unencrypted_key(pem: String) {
    black_box(SigningKey::from_pkcs8_pem(black_box(&pem)).unwrap());
}

#[library_benchmark(setup = encrypted_pem)]
fn detect_encrypted_key(pem: String) {
    black_box(SigningKey::from_pkcs8_pem(black_box(&pem)).err().unwrap());
}

#[library_benchmark(setup = encrypted_pem)]
fn load_encrypted_key(pem: String) {
    black_box(
        SigningKey::from_pkcs8_pem_with_password(black_box(&pem), black_box(PASSWORD)).unwrap(),
    );
}

library_benchmark_group!(
    name = signing_key_load;
    benchmarks = load_unencrypted_key, detect_encrypted_key, load_encrypted_key
);

main!(library_benchmark_groups = signing_key_load);
