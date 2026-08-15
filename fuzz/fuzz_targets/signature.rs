#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_bundle::BundleSignature;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<BundleSignature>(data);
});
