use crate::{BundleError, Diagnostic, Result};
use cedar_policy::{EntityTypeName, Schema};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use treetop_core::{AttrValue, LabelTarget, Labeler, RegexLabeler, Resource};

const MAX_LABEL_RULES: usize = 256;
const MAX_PATTERNS_PER_RULE: usize = 1_024;
const MAX_TOTAL_PATTERNS: usize = 4_096;
const MAX_REGEX_BYTES: usize = 16 * 1024;
const MAX_TOTAL_REGEX_BYTES: usize = 1024 * 1024;
const REGEX_SET_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const REGEX_SET_DFA_SIZE_LIMIT: usize = 1024 * 1024;
const INDIVIDUAL_REGEX_THRESHOLD: usize = 4;
const INDIVIDUAL_REGEX_SIZE_LIMIT: usize = REGEX_SET_SIZE_LIMIT / INDIVIDUAL_REGEX_THRESHOLD;
const INDIVIDUAL_REGEX_DFA_SIZE_LIMIT: usize =
    REGEX_SET_DFA_SIZE_LIMIT / INDIVIDUAL_REGEX_THRESHOLD;

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
    target: RawLabelTarget,
    field: String,
    patterns: Vec<RawLabelPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLabelTarget {
    resource_type: String,
    attribute: String,
}

/// A validated label rule.
#[derive(Clone, Serialize)]
pub struct LabelRule {
    target: LabelTarget,
    field: String,
    patterns: Vec<LabelPattern>,
    #[serde(skip)]
    runtime: Arc<dyn Labeler>,
}

#[derive(Debug, Clone)]
enum CompiledPatterns {
    Individual(Arc<Vec<Regex>>),
    Set(Arc<RegexSet>),
}

impl std::fmt::Debug for LabelRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabelRule")
            .field("target", &self.target)
            .field("field", &self.field)
            .field("patterns", &self.patterns)
            .finish_non_exhaustive()
    }
}

impl PartialEq for LabelRule {
    fn eq(&self, other: &Self) -> bool {
        self.target == other.target && self.field == other.field && self.patterns == other.patterns
    }
}

impl Eq for LabelRule {}

#[derive(Debug)]
struct RegexSetLabeler {
    target: LabelTarget,
    field: String,
    names: Vec<String>,
    compiled: Arc<RegexSet>,
}

impl Labeler for RegexSetLabeler {
    fn target(&self) -> &LabelTarget {
        &self.target
    }

    fn derive(&self, resource: &Resource) -> Option<AttrValue> {
        let Some(AttrValue::String(value)) = resource.attributes().get(&self.field) else {
            return None;
        };
        let labels = self
            .compiled
            .matches(value)
            .iter()
            .map(|index| AttrValue::String(self.names[index].clone()))
            .collect();
        Some(AttrValue::Set(labels))
    }
}

impl LabelRule {
    /// Validated exact resource type and derived attribute ownership.
    pub fn target(&self) -> &LabelTarget {
        &self.target
    }

    pub fn field(&self) -> &str {
        &self.field
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
        validate_document_limits(&raw)?;

        let mut diagnostics = Vec::new();
        let mut destinations = HashSet::new();
        let mut rules = Vec::with_capacity(raw.len());

        for (rule_index, raw_rule) in raw.into_iter().enumerate() {
            let location = format!("labels[{rule_index}]");
            let target =
                match LabelTarget::new(raw_rule.target.resource_type, raw_rule.target.attribute) {
                    Ok(target) => target,
                    Err(error) => {
                        diagnostics.push(Diagnostic::error(
                            "labels.invalid_target",
                            format!("{location}.target: {error}"),
                        ));
                        continue;
                    }
                };
            if raw_rule.field.trim().is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_field",
                    format!("{location}.field must not be empty"),
                ));
            }
            if raw_rule.field == target.attribute() {
                diagnostics.push(Diagnostic::error(
                    "labels.input_is_output",
                    format!("{location}.field and target.attribute must be different"),
                ));
            }
            if !destinations.insert(target.clone()) {
                diagnostics.push(Diagnostic::error(
                    "labels.duplicate_destination",
                    format!(
                        "duplicate label destination ({}, {})",
                        target.resource_type(),
                        target.attribute()
                    ),
                ));
            }
            if raw_rule.patterns.is_empty() {
                diagnostics.push(Diagnostic::error(
                    "labels.empty_patterns",
                    format!("{location}.patterns must not be empty"),
                ));
            }
            if raw_rule.patterns.len() > MAX_PATTERNS_PER_RULE {
                diagnostics.push(Diagnostic::error(
                    "labels.too_many_patterns",
                    format!(
                        "{location}.patterns contains more than {MAX_PATTERNS_PER_RULE} entries"
                    ),
                ));
            }

            let mut names = HashSet::new();
            let mut patterns = Vec::with_capacity(raw_rule.patterns.len());
            let mut patterns_valid =
                !raw_rule.patterns.is_empty() && raw_rule.patterns.len() <= MAX_PATTERNS_PER_RULE;
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
                if raw_pattern.regex.is_empty() {
                    diagnostics.push(Diagnostic::error(
                        "labels.empty_regex",
                        format!("{pattern_location}.regex must not be empty"),
                    ));
                    patterns_valid = false;
                } else if raw_pattern.regex.len() > MAX_REGEX_BYTES {
                    diagnostics.push(Diagnostic::error(
                        "labels.regex_too_large",
                        format!("{pattern_location}.regex exceeds {MAX_REGEX_BYTES} bytes"),
                    ));
                    patterns_valid = false;
                }
                patterns.push(LabelPattern {
                    name: raw_pattern.name,
                    regex: raw_pattern.regex,
                });
            }

            if patterns_valid {
                match compile_patterns(&patterns) {
                    Ok(compiled) => {
                        match runtime_labeler(target.clone(), &raw_rule.field, &patterns, compiled)
                        {
                            Ok(runtime) => rules.push(LabelRule {
                                target,
                                field: raw_rule.field,
                                patterns,
                                runtime,
                            }),
                            Err(error) => diagnostics.push(Diagnostic::error(
                                "labels.invalid_configuration",
                                format!("{location}: {error}"),
                            )),
                        }
                    }
                    Err(error) => diagnostics.push(Diagnostic::error(
                        "labels.invalid_regex",
                        format!("{location}.patterns cannot be compiled safely: {error}"),
                    )),
                }
            }
        }

        if diagnostics.is_empty() {
            Ok(Self(rules))
        } else {
            Err(BundleError::Validation(diagnostics))
        }
    }

    pub(crate) fn combine(sets: impl IntoIterator<Item = Self>) -> Result<Self> {
        let rules = sets.into_iter().flat_map(|set| set.0).collect::<Vec<_>>();
        validate_combined_limits(&rules)?;
        let mut destinations = HashSet::with_capacity(rules.len());
        let mut diagnostics = Vec::new();
        for rule in &rules {
            if !destinations.insert(rule.target()) {
                diagnostics.push(Diagnostic::error(
                    "labels.duplicate_destination",
                    format!(
                        "duplicate label destination ({}, {})",
                        rule.target.resource_type(),
                        rule.target.attribute()
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

    /// Return one scoped runtime owner per rule in configuration order.
    ///
    /// Targets and regex programs were validated at parsing time. Attribute names
    /// can repeat on disjoint resource types; duplicate tuples are rejected.
    pub fn to_labelers(&self) -> Vec<Arc<dyn Labeler>> {
        self.0
            .iter()
            .map(|rule| Arc::clone(&rule.runtime))
            .collect()
    }

    pub(crate) fn validate_schema(&self, schema: &Schema, schema_json: &Value) -> Vec<Diagnostic> {
        let known_types = schema
            .entity_types()
            .map(ToString::to_string)
            .collect::<HashSet<_>>();
        let mut diagnostics = Vec::new();
        for rule in &self.0 {
            if !known_types.contains(rule.target.resource_type()) {
                diagnostics.push(Diagnostic::error(
                    "labels.unknown_kind",
                    format!(
                        "label kind {} is not declared in the schema",
                        rule.target.resource_type()
                    ),
                ));
                continue;
            }
            let Some(attributes) = entity_attributes(schema_json, rule.target.resource_type())
            else {
                diagnostics.push(Diagnostic::error(
                    "labels.missing_shape",
                    format!(
                        "label kind {} has no record shape",
                        rule.target.resource_type()
                    ),
                ));
                continue;
            };
            match attributes.get(&rule.field) {
                Some(value) if is_string_type(value) => {}
                Some(value) => diagnostics.push(Diagnostic::error(
                    "labels.field_not_string",
                    format!(
                        "{}.{} must have schema type String, found {value}",
                        rule.target.resource_type(),
                        rule.field
                    ),
                )),
                None => diagnostics.push(Diagnostic::error(
                    "labels.field_missing",
                    format!(
                        "{}.{} is not declared in the schema",
                        rule.target.resource_type(),
                        rule.field
                    ),
                )),
            }
            match attributes.get(rule.target.attribute()) {
                Some(value) if is_string_set_type(value) => {}
                Some(value) => diagnostics.push(Diagnostic::error(
                    "labels.output_not_string_set",
                    format!(
                        "{}.{} must have schema type Set<String>, found {value}",
                        rule.target.resource_type(),
                        rule.target.attribute(),
                    ),
                )),
                None => diagnostics.push(Diagnostic::error(
                    "labels.output_missing",
                    format!(
                        "{}.{} is not declared in the schema",
                        rule.target.resource_type(),
                        rule.target.attribute()
                    ),
                )),
            }
        }
        diagnostics
    }
}

fn runtime_labeler(
    target: LabelTarget,
    field: &str,
    patterns: &[LabelPattern],
    compiled: CompiledPatterns,
) -> std::result::Result<Arc<dyn Labeler>, treetop_core::PolicyError> {
    let labeler: Arc<dyn Labeler> = match compiled {
        CompiledPatterns::Individual(compiled) => Arc::new(RegexLabeler::new(
            target,
            field,
            patterns
                .iter()
                .zip(compiled.iter())
                .map(|(pattern, regex)| (pattern.name.clone(), regex.clone()))
                .collect(),
        )?),
        CompiledPatterns::Set(compiled) => Arc::new(RegexSetLabeler {
            target,
            field: field.to_string(),
            names: patterns
                .iter()
                .map(|pattern| pattern.name.clone())
                .collect(),
            compiled,
        }),
    };
    Ok(labeler)
}

fn compile_patterns(
    patterns: &[LabelPattern],
) -> std::result::Result<CompiledPatterns, regex::Error> {
    if patterns.len() <= INDIVIDUAL_REGEX_THRESHOLD {
        let compiled = patterns
            .iter()
            .map(|pattern| {
                let mut builder = RegexBuilder::new(&pattern.regex);
                builder
                    .size_limit(INDIVIDUAL_REGEX_SIZE_LIMIT)
                    .dfa_size_limit(INDIVIDUAL_REGEX_DFA_SIZE_LIMIT);
                builder.build()
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(CompiledPatterns::Individual(Arc::new(compiled)))
    } else {
        let mut builder =
            RegexSetBuilder::new(patterns.iter().map(|pattern| pattern.regex.as_str()));
        builder
            .size_limit(REGEX_SET_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SET_DFA_SIZE_LIMIT);
        builder
            .build()
            .map(|compiled| CompiledPatterns::Set(Arc::new(compiled)))
    }
}

fn validate_document_limits(raw: &[RawLabelRule]) -> Result<()> {
    if raw.len() > MAX_LABEL_RULES {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.too_many_rules",
            format!("label document contains more than {MAX_LABEL_RULES} rules"),
        )]));
    }
    let total_patterns = raw
        .iter()
        .try_fold(0usize, |total, rule| total.checked_add(rule.patterns.len()))
        .unwrap_or(usize::MAX);
    if total_patterns > MAX_TOTAL_PATTERNS {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.too_many_patterns",
            format!("label document contains more than {MAX_TOTAL_PATTERNS} patterns"),
        )]));
    }
    let total_regex_bytes = raw
        .iter()
        .flat_map(|rule| &rule.patterns)
        .try_fold(0usize, |total, pattern| {
            total.checked_add(pattern.regex.len())
        })
        .unwrap_or(usize::MAX);
    if total_regex_bytes > MAX_TOTAL_REGEX_BYTES {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.regex_budget_exceeded",
            format!("label document regex sources exceed {MAX_TOTAL_REGEX_BYTES} total bytes"),
        )]));
    }
    Ok(())
}

fn validate_combined_limits(rules: &[LabelRule]) -> Result<()> {
    if rules.len() > MAX_LABEL_RULES {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.too_many_rules",
            format!("combined label document contains more than {MAX_LABEL_RULES} rules"),
        )]));
    }
    let total_patterns = rules
        .iter()
        .try_fold(0usize, |total, rule| total.checked_add(rule.patterns.len()))
        .unwrap_or(usize::MAX);
    if total_patterns > MAX_TOTAL_PATTERNS {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.too_many_patterns",
            format!("combined label document contains more than {MAX_TOTAL_PATTERNS} patterns"),
        )]));
    }
    let total_regex_bytes = rules
        .iter()
        .flat_map(|rule| &rule.patterns)
        .try_fold(0usize, |total, pattern| {
            total.checked_add(pattern.regex.len())
        })
        .unwrap_or(usize::MAX);
    if total_regex_bytes > MAX_TOTAL_REGEX_BYTES {
        return Err(BundleError::Validation(vec![Diagnostic::error(
            "labels.regex_budget_exceeded",
            format!(
                "combined label document regex sources exceed {MAX_TOTAL_REGEX_BYTES} total bytes"
            ),
        )]));
    }
    Ok(())
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
    use treetop_core::{LabelRegistryBuilder, LabelerApply};

    fn shared_output_rules() -> LabelSet {
        LabelSet::from_json_str(r#"[
            {"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"host","regex":"prod"}]},
            {"target": {"resource_type": "App::Bucket", "attribute": "labels"}, "field": "name","patterns":[{"name":"bucket","regex":"prod"}]}
        ]"#).unwrap()
    }

    #[test]
    fn shared_names_have_distinct_scoped_owners_and_replace_forged_labels() {
        let labelers = shared_output_rules().to_labelers();
        assert_eq!(labelers.len(), 2);
        let mut builder = LabelRegistryBuilder::new();
        for labeler in labelers {
            builder = builder.add_labeler(labeler);
        }
        let registry = builder.build().unwrap();
        for (kind, expected) in [("App::Host", "host"), ("App::Bucket", "bucket")] {
            let mut resource = Resource::new(kind, "one")
                .unwrap()
                .with_attr("name", AttrValue::String("prod".into()))
                .with_attr("labels", AttrValue::String("forged".into()));
            registry.apply(&mut resource);
            assert_eq!(
                resource.attributes().get("labels"),
                Some(&AttrValue::Set(vec![AttrValue::String(expected.into())]))
            );
            let once = resource.clone();
            registry.apply(&mut resource);
            assert_eq!(resource, once);
        }
    }

    #[test]
    fn scoped_owners_remove_missing_derivations_and_preserve_other_types() {
        let mut builder = LabelRegistryBuilder::new();
        for labeler in shared_output_rules().to_labelers() {
            builder = builder.add_labeler(labeler);
        }
        let registry = builder.build().unwrap();
        for kind in ["App::Host", "App::Bucket"] {
            let mut resource = Resource::new(kind, "one")
                .unwrap()
                .with_attr("labels", AttrValue::String("forged".into()));
            registry.apply(&mut resource);
            assert!(!resource.attributes().contains_key("labels"));
        }
        let mut other = Resource::new("App::Other", "one")
            .unwrap()
            .with_attr("labels", AttrValue::String("application input".into()));
        let original = other.clone();
        registry.apply(&mut other);
        assert_eq!(other, original);
    }

    #[test]
    fn shared_output_preserves_empty_match_set() {
        let labeler = shared_output_rules().to_labelers().remove(0);
        let mut resource = Resource::new("App::Host", "one")
            .unwrap()
            .with_attr("name", AttrValue::String("development".into()));
        labeler.apply(&mut resource);
        assert_eq!(
            resource.attributes().get("labels"),
            Some(&AttrValue::Set(vec![]))
        );
    }

    #[test]
    fn combined_label_documents_preserve_distinct_targets_and_reject_duplicates() {
        let labels = shared_output_rules();
        let first = LabelSet(vec![labels.0[0].clone()]);
        let second = LabelSet(vec![labels.0[1].clone()]);
        assert_eq!(
            LabelSet::combine([first.clone(), second])
                .unwrap()
                .to_labelers()
                .len(),
            2
        );
        assert!(LabelSet::combine([first.clone(), first]).is_err());
    }

    #[test]
    fn both_regex_backends_reject_reserved_output_at_parse_boundary() {
        for count in [1, 5] {
            let patterns: Vec<_> = (0..count)
                .map(|i| {
                    serde_json::json!({
                        "name": format!("label-{i}"), "regex": "prod",
                    })
                })
                .collect();
            let source = serde_json::json!([{
                "target": {"resource_type": "App::Host", "attribute": "id"}, "field": "name", "patterns":patterns,
            }])
            .to_string();
            let error = LabelSet::from_json_str(&source).unwrap_err();
            assert!(
                error
                    .diagnostics()
                    .iter()
                    .any(|d| d.code == "labels.invalid_target")
            );
        }
    }

    #[test]
    fn old_and_incomplete_target_syntax_is_rejected() {
        for source in [
            r#"[{"kind":"App::Host","output":"labels","field":"name","patterns":[]}]"#,
            r#"[{"target":{"resource_type":"App::Host"},"field":"name","patterns":[]}]"#,
            r#"[{"target":{"resource_type":"App::Host","attribute":"labels","scope":"*"},"field":"name","patterns":[]}]"#,
            r#"[{"target":{"resource_type":"App::Host","attribute":"labels"},"output":"labels","field":"name","patterns":[]}]"#,
        ] {
            let error = LabelSet::from_json_str(source).unwrap_err();
            assert_eq!(error.diagnostics()[0].code, "labels.invalid_json");
        }
    }

    #[test]
    fn strict_label_validation_rejects_unknown_fields() {
        let error = LabelSet::from_json_str(
            r#"[{"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"prod","regex":"prod","extra":true}]}]"#,
        )
        .unwrap_err();
        assert!(error.diagnostics()[0].message.contains("unknown field"));
    }

    #[test]
    fn label_set_converts_to_runtime_labelers() {
        let labels = LabelSet::from_json_str(
            r#"[{"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
        )
        .unwrap();
        assert_eq!(labels.to_labelers().len(), 1);
    }

    #[test]
    fn regex_set_labeler_returns_all_matches_and_replaces_untrusted_output() {
        let labels = LabelSet::from_json_str(
            r#"[{"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"prod","regex":"^prod"},{"name":"database","regex":"db$"},{"name":"staging","regex":"^staging"},{"name":"cache","regex":"cache$"},{"name":"worker","regex":"worker"}]}]"#,
        )
        .unwrap();
        let labeler = labels.to_labelers().pop().unwrap();
        let mut resource = Resource::new("App::Host", "one")
            .unwrap()
            .with_attr("name", AttrValue::String("prod-db".to_string()))
            .with_attr(
                "labels",
                AttrValue::Set(vec![AttrValue::String("forged".to_string())]),
            );

        labeler.apply(&mut resource);

        assert_eq!(
            resource.attributes().get("labels"),
            Some(&AttrValue::Set(vec![
                AttrValue::String("prod".to_string()),
                AttrValue::String("database".to_string()),
            ]))
        );
    }

    #[test]
    fn label_document_pattern_budget_is_enforced_before_compilation() {
        let patterns = (0..=MAX_TOTAL_PATTERNS)
            .map(|index| {
                serde_json::json!({
                    "name": format!("pattern-{index}"),
                    "regex": "a",
                })
            })
            .collect::<Vec<_>>();
        let source = serde_json::json!([{
            "target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name",
            "patterns": patterns,
        }])
        .to_string();

        let error = LabelSet::from_json_str(&source).unwrap_err();

        assert_eq!(error.diagnostics()[0].code, "labels.too_many_patterns");
    }

    #[test]
    fn combined_label_sets_reapply_document_limits() {
        let labels = LabelSet::from_json_str(
            r#"[{"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
        )
        .unwrap();

        let error =
            LabelSet::combine(std::iter::repeat_n(labels, MAX_LABEL_RULES + 1)).unwrap_err();

        assert_eq!(error.diagnostics()[0].code, "labels.too_many_rules");
    }

    #[test]
    fn schema_validation_resolves_common_record_shapes() {
        let labels = LabelSet::from_json_str(
            r#"[{"target": {"resource_type": "App::Host", "attribute": "labels"}, "field": "name","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
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
