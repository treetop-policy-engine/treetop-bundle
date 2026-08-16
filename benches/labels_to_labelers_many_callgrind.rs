mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::LabelSet;

#[library_benchmark(setup = support::many_label_set)]
fn build_many_runtime_labelers(labels: LabelSet) {
    let _ = labels.to_labelers();
}

library_benchmark_group!(
    name = labels_to_labelers_many;
    benchmarks = build_many_runtime_labelers
);

main!(library_benchmark_groups = labels_to_labelers_many);
