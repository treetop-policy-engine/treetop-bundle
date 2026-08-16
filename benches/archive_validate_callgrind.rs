#[path = "support/archive.rs"]
mod support;

use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_bundle::{ArchiveLimits, BundleArchive, SignaturePolicy, TrustStore};

#[library_benchmark(setup = support::unsigned_archive)]
fn validate_archive(archive: BundleArchive) {
    let _ = archive
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::default(),
        )
        .unwrap();
}

library_benchmark_group!(
    name = archive_validate;
    benchmarks = validate_archive
);

main!(library_benchmark_groups = archive_validate);
