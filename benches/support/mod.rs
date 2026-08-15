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
