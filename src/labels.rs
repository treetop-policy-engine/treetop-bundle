use crate::{BundleError, Diagnostic, Result};
use cedar_policy::{EntityTypeName, Schema};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use treetop_core::{Labeler, RegexLabeler};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLabelPattern {
    name: String,
    regex: String,
}

/// A validated regular-expression label mapping.
#[derive(Debug, Clone, Serialize)]
pub struct LabelPattern {
    name: String,
    regex: String,
    #[serde(skip)]
    compiled: Regex,
}

impl PartialEq for LabelPattern {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.regex == other.regex
    }
}

impl Eq for LabelPattern {}

impl LabelPattern {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn regex(&self) -> &str {
        &self.regex
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLabelRule {
    kind: String,
    field: String,
    output: String,
    patterns: Vec<RawLabelPattern>,
}

/// A validated label rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabelRule {
    kind: String,
    field: String,
    output: String,
    patterns: Vec<LabelPattern>,
}

impl LabelRule {
    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn field(&self) -> &str {
        &self.field
    }

    pub fn output(&self) -> &str {
        &self.output
    }

    pub fn patterns(&self) -> &[LabelPattern] {
        &self.patterns
    }
}

/// A validated set of label rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct LabelSet(Vec<LabelRule>);

impl LabelSet {
    /// Parse and strictly validate a JSON label document.
    pub fn from_json_str(input: &str) -> Result<Self> {
        let raw: Vec<RawLabelRule> = serde_json::from_str(input).map_err(|error| {
            let mut diagnostic = Diagnostic::error("labels.invalid_json", error.to_string());
            diagnostic.line = Some(error.line());
            diagnostic.column = Some(error.column());
            BundleError::Validation(vec![diagnostic])
        })?;
        Self::from_raw(raw)
    }

    /// Validate label entity and attribute types against a complete Cedar JSON schema.
    pub fn validate_schema_json_str(&self, schema_source: &str) -> Result<()> {
        let schema_json: Value = serde_json::from_str(schema_source).map_err(|error| {
            BundleError::Validation(vec![Diagnostic::error(
                "schema.invalid_json",
                error.to_string(),
            )])
        })?;
        let schema = Schema::from_json_value(schema_json.clone()).map_err(|error| {
            BundleError::Validation(vec![Diagnostic::error(
                "schema.aggregate_invalid",
                error.to_string(),
            )])
        })?;
        let diagnostics = self.validate_schema(&schema, &schema_json);
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(BundleError::Validation(diagnostics))
        }
    }

    fn from_raw(raw: Vec<RawLabelRule>) -> Result<Self> {
        let mut diagnostics = Vec::new();
        let mut destinations = HashSet::new();
        let mut rules = Vec::with_capacity(raw.len());

        for (rule_index, raw_rule) in raw.into_iter().enumerate() {
            let location = format!("labels[{rule_index}]");
            if raw_rule.kind.trim().is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_kind",
                    format!("{location}.kind must not be empty"),
                ));
            } else if raw_rule.kind.parse::<EntityTypeName>().is_err() {
                diagnostics.push(Diagnostic::error(
                    "labels.invalid_kind",
                    format!("{location}.kind is not a Cedar entity type"),
                ));
            }
            if raw_rule.field.trim().is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_field",
                    format!("{location}.field must not be empty"),
                ));
            }
            if raw_rule.output.trim().is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_output",
                    format!("{location}.output must not be empty"),
                ));
            }
            if raw_rule.field == raw_rule.output {
                diagnostics.push(Diagnostic::error(
                    "labels.input_is_output",
                    format!("{location}.field and output must be different"),
                ));
            }
            if !destinations.insert((raw_rule.kind.clone(), raw_rule.output.clone())) {
                diagnostics.push(Diagnostic::error(
                    "labels.duplicate_destination",
                    format!(
                        "duplicate label destination ({}, {})",
                        raw_rule.kind, raw_rule.output
                    ),
                ));
            }
            if raw_rule.patterns.is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_patterns",
                    format!("{location}.patterns must not be empty"),
                ));
            }

            let mut names = HashSet::new();
            let mut patterns = Vec::with_capacity(raw_rule.patterns.len());
            for (pattern_index, raw_pattern) in raw_rule.patterns.into_iter().enumerate() {
                let pattern_location = format!("{location}.patterns[{pattern_index}]");
                if raw_pattern.name.trim().is_empty() {
                    diagnostics.push(Diagnostic::error(
                        "labels.empty_pattern_name",
                        format!("{pattern_location}.name must not be empty"),
                    ));
                }
                if !names.insert(raw_pattern.name.clone()) {
                    diagnostics.push(Diagnostic::error(
                        "labels.duplicate_pattern_name",
                        format!(
                            "duplicate pattern name {:?} in {location}",
                            raw_pattern.name
                        ),
                    ));
                }
                let compiled = if raw_pattern.regex.is_empty() {
                    diagnostics.push(Diagnostic::error(
                        "labels.empty_regex",
                        format!("{pattern_location}.regex must not be empty"),
                    ));
                    None
                } else {
                    match Regex::new(&raw_pattern.regex) {
                        Ok(regex) => Some(regex),
                        Err(error) => {
                            diagnostics.push(Diagnostic::error(
                                "labels.invalid_regex",
                                format!("{pattern_location}.regex is invalid: {error}"),
                            ));
                            None
                        }
                    }
                };
                if let Some(compiled) = compiled {
                    patterns.push(LabelPattern {
                        name: raw_pattern.name,
                        regex: raw_pattern.regex,
                        compiled,
                    });
                }
            }

            rules.push(LabelRule {
                kind: raw_rule.kind,
                field: raw_rule.field,
                output: raw_rule.output,
                patterns,
            });
        }

        if diagnostics.is_empty() {
            Ok(Self(rules))
        } else {
            Err(BundleError::Validation(diagnostics))
        }
    }

    pub(crate) fn combine(sets: impl IntoIterator<Item = Self>) -> Result<Self> {
        let rules = sets.into_iter().flat_map(|set| set.0).collect::<Vec<_>>();
        let mut destinations = HashSet::with_capacity(rules.len());
        let mut diagnostics = Vec::new();
        for rule in &rules {
            if !destinations.insert((&rule.kind, &rule.output)) {
                diagnostics.push(Diagnostic::error(
                    "labels.duplicate_destination",
                    format!(
                        "duplicate label destination ({}, {})",
                        rule.kind, rule.output
                    ),
                ));
            }
        }
        if diagnostics.is_empty() {
            Ok(Self(rules))
        } else {
            Err(BundleError::Validation(diagnostics))
        }
    }

    pub fn rules(&self) -> &[LabelRule] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convert this validated set into Treetop's existing runtime labelers.
    pub fn to_labelers(&self) -> Vec<Arc<dyn Labeler>> {
        self.0
            .iter()
            .map(|rule| {
                let patterns = rule
                    .patterns
                    .iter()
                    .map(|pattern| (pattern.name.clone(), pattern.compiled.clone()))
                    .collect();
                Arc::new(RegexLabeler::new(
                    rule.kind.clone(),
                    rule.field.clone(),
                    rule.output.clone(),
                    patterns,
                )) as Arc<dyn Labeler>
            })
            .collect()
    }

    pub(crate) fn validate_schema(&self, schema: &Schema, schema_json: &Value) -> Vec<Diagnostic> {
        let known_types = schema
            .entity_types()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        let mut diagnostics = Vec::new();
        for rule in &self.0 {
            if !known_types.contains(&rule.kind) {
                diagnostics.push(Diagnostic::error(
                    "labels.unknown_kind",
                    format!("label kind {} is not declared in the schema", rule.kind),
                ));
                continue;
            }
            let Some(attributes) = entity_attributes(schema_json, &rule.kind) else {
                diagnostics.push(Diagnostic::error(
                    "labels.missing_shape",
                    format!("label kind {} has no record shape", rule.kind),
                ));
                continue;
            };
            match attributes.get(&rule.field) {
                Some(value) if is_string_type(value) => {}
                Some(value) => diagnostics.push(Diagnostic::error(
                    "labels.field_not_string",
                    format!(
                        "{}.{} must have schema type String, found {value}",
                        rule.kind, rule.field
                    ),
                )),
                None => diagnostics.push(Diagnostic::error(
                    "labels.field_missing",
                    format!("{}.{} is not declared in the schema", rule.kind, rule.field),
                )),
            }
            match attributes.get(&rule.output) {
                Some(value) if is_string_set_type(value) => {}
                Some(value) => diagnostics.push(Diagnostic::error(
                    "labels.output_not_string_set",
                    format!(
                        "{}.{} must have schema type Set<String>, found {value}",
                        rule.kind, rule.output,
                    ),
                )),
                None => diagnostics.push(Diagnostic::error(
                    "labels.output_missing",
                    format!(
                        "{}.{} is not declared in the schema",
                        rule.kind, rule.output
                    ),
                )),
            }
        }
        diagnostics
    }
}

fn entity_attributes<'a>(
    schema_json: &'a Value,
    kind: &str,
) -> Option<&'a serde_json::Map<String, Value>> {
    let parsed = kind.parse::<EntityTypeName>().ok()?;
    let namespace = parsed.namespace().to_string();
    let namespace_definition = schema_json.as_object()?.get(&namespace)?;
    let definition = namespace_definition
        .get("entityTypes")?
        .get(parsed.basename())?;
    record_attributes(
        schema_json,
        &namespace,
        definition.get("shape")?,
        &mut HashSet::new(),
    )
}

fn record_attributes<'a>(
    schema_json: &'a Value,
    namespace: &str,
    shape: &'a Value,
    visited: &mut HashSet<String>,
) -> Option<&'a serde_json::Map<String, Value>> {
    if shape.get("type").and_then(Value::as_str) == Some("Record") {
        return shape.get("attributes")?.as_object();
    }
    if shape.get("type").and_then(Value::as_str) != Some("EntityOrCommon") {
        return None;
    }
    let name = shape.get("name")?.as_str()?;
    let (common_namespace, basename) = name
        .rsplit_once("::")
        .map_or((namespace, name), |(namespace, basename)| {
            (namespace, basename)
        });
    let qualified_name = format!("{common_namespace}::{basename}");
    if !visited.insert(qualified_name) {
        return None;
    }
    let common = schema_json
        .as_object()?
        .get(common_namespace)?
        .get("commonTypes")?
        .get(basename)?;
    record_attributes(schema_json, common_namespace, common, visited)
}

fn is_string_type(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("String")
        || (value.get("type").and_then(Value::as_str) == Some("EntityOrCommon")
            && value.get("name").and_then(Value::as_str) == Some("String"))
}

fn is_string_set_type(value: &Value) -> bool {
    value.get("type").and_then(Value::as_str) == Some("Set")
        && value.get("element").is_some_and(is_string_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_label_validation_rejects_unknown_fields() {
        let error = LabelSet::from_json_str(
            r#"[{"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"prod","regex":"prod","extra":true}]}]"#,
        )
        .unwrap_err();
        assert!(error.diagnostics()[0].message.contains("unknown field"));
    }

    #[test]
    fn label_set_converts_to_runtime_labelers() {
        let labels = LabelSet::from_json_str(
            r#"[{"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
        )
        .unwrap();
        assert_eq!(labels.to_labelers().len(), 1);
    }

    #[test]
    fn schema_validation_resolves_common_record_shapes() {
        let labels = LabelSet::from_json_str(
            r#"[{"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
        )
        .unwrap();
        let schema = r#"{
          "App": {
            "commonTypes": {
              "HostShape": {
                "type": "Record",
                "attributes": {
                  "name": {"type": "String", "required": true},
                  "labels": {
                    "type": "Set",
                    "element": {"type": "String"},
                    "required": false
                  }
                },
                "additionalAttributes": false
              }
            },
            "entityTypes": {
              "Host": {
                "shape": {"type": "EntityOrCommon", "name": "HostShape"}
              }
            },
            "actions": {}
          }
        }"#;

        labels.validate_schema_json_str(schema).unwrap();
    }
}
