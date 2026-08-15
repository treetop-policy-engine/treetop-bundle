mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::LabelSet;

fn label_set() -> LabelSet {
    LabelSet::from_json_str(support::LABELS_JSON).unwrap()
}

#[library_benchmark(setup = label_set)]
fn build_runtime_labelers(labels: LabelSet) {
    let _ = labels.to_labelers();
}

library_benchmark_group!(name = labels_to_labelers; benchmarks = build_runtime_labelers);

main!(library_benchmark_groups = labels_to_labelers);
