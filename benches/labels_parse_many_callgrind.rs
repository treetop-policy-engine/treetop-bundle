mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::LabelSet;

fn many_labels_json() -> String {
    support::labels_json(1_024)
}

#[library_benchmark(setup = many_labels_json)]
fn parse_many_validated_labels(source: String) {
    let _ = LabelSet::from_json_str(&source).unwrap();
}

library_benchmark_group!(
    name = labels_parse_many;
    benchmarks = parse_many_validated_labels
);

main!(library_benchmark_groups = labels_parse_many);
