#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_bundle::{ArchiveLimits, BundleArchive, SignaturePolicy, TrustStore};

fuzz_target!(|data: &[u8]| {
    let _ = BundleArchive::from_bytes(data.to_vec()).validate(
        SignaturePolicy::AllowUnsigned,
        &TrustStore::new(),
        ArchiveLimits::new(64 * 1024, 256 * 1024).unwrap(),
    );
});
