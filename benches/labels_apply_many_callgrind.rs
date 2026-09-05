use treetop_core::LabelerApply;
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};

#[library_benchmark(setup = support::apply_many_fixture)]
fn apply_many_runtime_patterns(mut fixture: support::ApplyFixture) {
    fixture.labeler.apply(&mut fixture.resource);
}

library_benchmark_group!(
    name = labels_apply_many;
    benchmarks = apply_many_runtime_patterns
);

main!(library_benchmark_groups = labels_apply_many);
