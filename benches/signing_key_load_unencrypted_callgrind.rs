#[path = "support/signing.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_bundle::SigningKey;

#[library_benchmark(setup = support::unencrypted_pem)]
fn load_unencrypted_key(pem: String) {
    black_box(SigningKey::from_pkcs8_pem(black_box(&pem)).unwrap());
}

library_benchmark_group!(
    name = signing_key_load_unencrypted;
    benchmarks = load_unencrypted_key
);

main!(library_benchmark_groups = signing_key_load_unencrypted);
