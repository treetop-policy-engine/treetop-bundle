mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::LabelSet;

#[library_benchmark]
fn parse_validated_labels() {
    let _ = LabelSet::from_json_str(support::LABELS_JSON).unwrap();
}

library_benchmark_group!(name = labels_parse; benchmarks = parse_validated_labels);

main!(library_benchmark_groups = labels_parse);
