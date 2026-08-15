#![no_main]

use libfuzzer_sys::fuzz_target;
use treetop_bundle::LabelSet;

fuzz_target!(|data: &[u8]| {
    if let Ok(source) = std::str::from_utf8(data) {
        let _ = LabelSet::from_json_str(source);
    }
});
