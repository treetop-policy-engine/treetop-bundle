#![no_main]

use libfuzzer_sys::fuzz_target;
use std::fs;
use treetop_bundle::{BundleManifest, ModuleManifest};

fuzz_target!(|data: &[u8]| {
    let temporary = tempfile::tempdir().unwrap();
    let module_path = temporary.path().join("treetop-module.toml");
    fs::write(&module_path, data).unwrap();
    let _ = ModuleManifest::from_path(&module_path);

    let bundle_path = temporary.path().join("treetop-bundle.toml");
    fs::write(&bundle_path, data).unwrap();
    let _ = BundleManifest::from_path(bundle_path);
});
