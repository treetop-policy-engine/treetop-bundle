#[path = "support/archive.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::ArchiveLimits;

#[library_benchmark(setup = support::resign_fixture)]
fn resign_archive(fixture: support::ResignFixture) {
    let _ = fixture
        .archive
        .resign(&fixture.key, ArchiveLimits::default())
        .unwrap();
}

library_benchmark_group!(
    name = archive_resign;
    benchmarks = resign_archive
);

main!(library_benchmark_groups = archive_resign);
