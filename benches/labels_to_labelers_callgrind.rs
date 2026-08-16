mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::LabelSet;
use treetop_core::{AttrValue, Labeler, Resource};

fn label_set() -> LabelSet {
    LabelSet::from_json_str(support::LABELS_JSON).unwrap()
}

#[library_benchmark(setup = label_set)]
fn build_runtime_labelers(labels: LabelSet) {
    let _ = labels.to_labelers();
}

fn many_label_set() -> LabelSet {
    LabelSet::from_json_str(&support::labels_json(1_024)).unwrap()
}

#[library_benchmark(setup = many_label_set)]
fn build_many_runtime_labelers(labels: LabelSet) {
    let _ = labels.to_labelers();
}

struct ApplyFixture {
    labeler: std::sync::Arc<dyn Labeler>,
    resource: Resource,
}

fn apply_fixture() -> ApplyFixture {
    let labels = many_label_set();
    ApplyFixture {
        labeler: labels.to_labelers().pop().unwrap(),
        resource: Resource::new("Example::Host", "benchmark")
            .with_attr("name", AttrValue::String("host-1023".to_string())),
    }
}

#[library_benchmark(setup = apply_fixture)]
fn apply_many_runtime_patterns(mut fixture: ApplyFixture) {
    fixture.labeler.apply(&mut fixture.resource);
}

library_benchmark_group!(
    name = labels_to_labelers;
    benchmarks =
        build_runtime_labelers,
        build_many_runtime_labelers,
        apply_many_runtime_patterns
);

main!(library_benchmark_groups = labels_to_labelers);
