#[path = "support/signing.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_bundle::SigningKey;

#[library_benchmark(setup = support::encrypted_pem)]
fn detect_encrypted_key(pem: String) {
    black_box(SigningKey::from_pkcs8_pem(black_box(&pem)).err().unwrap());
}

library_benchmark_group!(
    name = signing_key_detect_encrypted;
    benchmarks = detect_encrypted_key
);

main!(library_benchmark_groups = signing_key_detect_encrypted);
