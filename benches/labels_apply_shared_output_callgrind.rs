mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_core::LabelerApply;

#[library_benchmark(setup = support::apply_shared_output_fixture)]
fn apply_shared_output(mut fixture: support::ApplyFixture) {
    fixture.labeler.apply(&mut fixture.resource);
}

library_benchmark_group!(
    name = labels_apply_shared_output;
    benchmarks = apply_shared_output
);

main!(library_benchmark_groups = labels_apply_shared_output);
