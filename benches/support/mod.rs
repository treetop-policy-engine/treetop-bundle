#![allow(dead_code)]

use std::sync::Arc;
use treetop_bundle::LabelSet;
use treetop_core::{AttrValue, Labeler, Resource};

pub const LABELS_JSON: &str = r#"[
  {
    "kind": "Example::Photo",
    "field": "name",
    "output": "labels",
    "patterns": [
      {"name": "portrait", "regex": "(?i)(^|/)portraits?/"},
      {"name": "raw", "regex": "(?i)\\.(cr2|nef|arw)$"},
      {"name": "archive", "regex": "^archive/[0-9]{4}/"}
    ]
  },
  {
    "kind": "Example::Document",
    "field": "path",
    "output": "classifications",
    "patterns": [
      {"name": "finance", "regex": "(?i)(^|/)finance/"},
      {"name": "legal", "regex": "(?i)(^|/)legal/"},
      {"name": "confidential", "regex": "(?i)confidential"}
    ]
  }
]"#;

pub fn labels_json(pattern_count: usize) -> String {
    let patterns = (0..pattern_count)
        .map(|index| {
            serde_json::json!({
                "name": format!("label-{index}"),
                "regex": format!("^host-{index}$"),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!([{
        "kind": "Example::Host",
        "field": "name",
        "output": "labels",
        "patterns": patterns,
    }])
    .to_string()
}

pub fn many_label_set() -> LabelSet {
    LabelSet::from_json_str(&labels_json(1_024)).unwrap()
}

pub struct ApplyFixture {
    pub labeler: Arc<dyn Labeler>,
    pub resource: Resource,
}

pub fn apply_many_fixture() -> ApplyFixture {
    let labels = many_label_set();
    ApplyFixture {
        labeler: labels.to_labelers().pop().unwrap(),
        resource: Resource::new("Example::Host", "benchmark")
            .with_attr("name", AttrValue::String("host-1023".to_string())),
    }
}
