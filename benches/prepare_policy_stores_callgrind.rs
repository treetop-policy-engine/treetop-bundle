#[path = "support/archive.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::ValidatedBundle;

#[library_benchmark(setup = support::validated_policy_store_bundle)]
fn build_partitioned_engine(bundle: ValidatedBundle) {
    let _ = bundle.prepare_engine_with_policy_stores().unwrap();
}

library_benchmark_group!(
    name = prepare_policy_stores;
    benchmarks = build_partitioned_engine
);

main!(library_benchmark_groups = prepare_policy_stores);
