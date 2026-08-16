#[path = "support/signing.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_bundle::SigningKey;

#[library_benchmark(setup = support::encrypted_pem)]
fn load_encrypted_key(pem: String) {
    black_box(
        SigningKey::from_pkcs8_pem_with_password(black_box(&pem), black_box(support::PASSWORD))
            .unwrap(),
    );
}

library_benchmark_group!(
    name = signing_key_load_encrypted;
    benchmarks = load_encrypted_key
);

main!(library_benchmark_groups = signing_key_load_encrypted);
