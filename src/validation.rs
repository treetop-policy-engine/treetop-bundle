use crate::manifest::namespace_owns;
use crate::{
    BundleError, BundleManifest, Diagnostic, DiagnosticSeverity, LabelSet, ModuleManifest,
    ModuleRole, Result,
};
use cedar_policy::pst::{
    ActionConstraint as PstActionConstraint, Clause, EntityOrSlot, Expr, Literal,
    PrincipalConstraint as PstPrincipalConstraint, ResourceConstraint as PstResourceConstraint,
};
use cedar_policy::{
    Policy, PolicyId, PolicySet, Schema, SchemaFragment, ValidationMode, Validator,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ModuleRecord {
    pub name: String,
    pub namespace: String,
    pub imports: Vec<String>,
    pub role: ModuleRole,
    pub policy_ids: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct BundleParts {
    pub name: String,
    pub modules: Vec<ModuleRecord>,
    pub policies: String,
    pub schema_json: Option<Value>,
    pub labels: LabelSet,
    pub policy_ids: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Result of checking a standalone Cedar policy document.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyCheck {
    pub(crate) diagnostics: Vec<Diagnostic>,
}

impl PolicyCheck {
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub fn is_valid(&self, deny_warnings: bool) -> bool {
        !self.diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                || (deny_warnings && diagnostic.severity == DiagnosticSeverity::Warning)
        })
    }
}

/// Check policy syntax and optionally validate it against a complete schema and labels.
pub fn check_policy(
    policy_source: &str,
    schema_source: Option<&str>,
    labels_source: Option<&str>,
) -> Result<PolicyCheck> {
    let mut diagnostics = Vec::new();
    let policy_set = match policy_source.parse::<PolicySet>() {
        Ok(policy_set) => Some(policy_set),
        Err(error) => {
            diagnostics.push(Diagnostic::error("policy.syntax", error.to_string()));
            None
        }
    };
    let labels = match labels_source {
        Some(source) => match LabelSet::from_json_str(source) {
            Ok(labels) => Some(labels),
            Err(BundleError::Validation(mut label_diagnostics)) => {
                diagnostics.append(&mut label_diagnostics);
                None
            }
            Err(error) => return Err(error),
        },
        None => None,
    };
    let schema = match schema_source {
        Some(source) => match parse_schema_fragment(source) {
            Ok((fragment, schema_warnings)) => {
                diagnostics.extend(schema_warnings);
                match Schema::from_schema_fragments([fragment.clone()]) {
                    Ok(schema) => {
                        let json = fragment
                            .to_json_value()
                            .map_err(|error| BundleError::Serialization(error.to_string()))?;
                        Some((schema, json))
                    }
                    Err(error) => {
                        diagnostics.push(Diagnostic::error("schema.invalid", error.to_string()));
                        None
                    }
                }
            }
            Err(error) => {
                diagnostics.push(Diagnostic::error("schema.syntax", error));
                None
            }
        },
        None => None,
    };

    if let (Some(policy_set), Some((schema, _))) = (&policy_set, &schema) {
        validate_policy_set(policy_set, schema, &mut diagnostics);
    }
    if let (Some(labels), Some((schema, schema_json))) = (&labels, &schema) {
        diagnostics.extend(labels.validate_schema(schema, schema_json));
    } else if labels.is_some() && schema.is_none() {
        diagnostics.push(Diagnostic::warning(
            "labels.schema_check_skipped",
            "label/schema compatibility was not checked because no schema was provided",
        ));
    }

    Ok(PolicyCheck { diagnostics })
}

/// Check one module in isolation. Declared imports are accepted but need not be present.
pub fn check_module(path: impl AsRef<Path>) -> Result<PolicyCheck> {
    let module = ModuleManifest::from_path(path)?;
    let manifest = BundleManifest::for_single_module(module);
    let parts = compile_manifest(&manifest)?;
    Ok(PolicyCheck {
        diagnostics: parts.diagnostics,
    })
}

pub(crate) fn compile_manifest(manifest: &BundleManifest) -> Result<BundleParts> {
    let mut diagnostics = Vec::new();
    let mut policy_text = String::new();
    let mut policy_ids = BTreeSet::new();
    let mut aggregate_policy_set = PolicySet::new();
    let mut aggregate_policy_index = 0usize;
    let mut aggregate_policy_set_valid = true;
    let mut modules = Vec::with_capacity(manifest.modules().len());
    let mut schema_json = Value::Object(Map::new());
    let mut has_schema = false;
    let mut label_sets = Vec::new();

    for selected in manifest.modules() {
        let module = selected.manifest();
        let mut module_record = ModuleRecord {
            name: module.name().to_string(),
            namespace: module.namespace().to_string(),
            imports: module.imports().to_vec(),
            role: selected.role(),
            policy_ids: Vec::new(),
        };
        let mut module_policy_ids = Vec::new();
        for relative_path in module.policies() {
            let path = module.input_path(relative_path);
            let source = read_utf8(&path)?;
            let normalized = normalize_text(&source);
            let parsed = match normalized.parse::<PolicySet>() {
                Ok(parsed) => parsed,
                Err(error) => {
                    diagnostics.push(
                        Diagnostic::error("policy.syntax", error.to_string())
                            .in_module(module.name())
                            .at_path(relative_path),
                    );
                    continue;
                }
            };
            validate_module_policies(
                &parsed,
                &module_record,
                relative_path,
                &mut module_policy_ids,
                &mut policy_ids,
                &mut diagnostics,
            );
            for policy in parsed.policies().filter(|policy| policy.is_static()) {
                let policy = policy.new_id(PolicyId::new(format!(
                    "treetop-bundle-{aggregate_policy_index}"
                )));
                aggregate_policy_index += 1;
                if let Err(error) = aggregate_policy_set.add(policy) {
                    diagnostics.push(Diagnostic::error(
                        "policy.aggregate_build",
                        error.to_string(),
                    ));
                    aggregate_policy_set_valid = false;
                }
            }
            policy_text.push_str("// treetop-module: ");
            policy_text.push_str(&single_line(module.name()));
            policy_text.push_str("; path: ");
            policy_text.push_str(&single_line(relative_path));
            policy_text.push('\n');
            policy_text.push_str(&normalized);
        }

        for relative_path in module.schemas() {
            has_schema = true;
            let path = module.input_path(relative_path);
            let source = read_utf8(&path)?;
            match parse_schema_fragment(&source) {
                Ok((fragment, warnings)) => {
                    diagnostics.extend(warnings.into_iter().map(|diagnostic| {
                        diagnostic.in_module(module.name()).at_path(relative_path)
                    }));
                    let fragment_json = fragment
                        .to_json_value()
                        .map_err(|error| BundleError::Serialization(error.to_string()))?;
                    validate_schema_ownership(
                        &fragment_json,
                        module.name(),
                        module.namespace(),
                        relative_path,
                        &mut diagnostics,
                    );
                    merge_schema_fragment(
                        &mut schema_json,
                        fragment_json,
                        module.name(),
                        relative_path,
                        &mut diagnostics,
                    );
                }
                Err(error) => diagnostics.push(
                    Diagnostic::error("schema.syntax", error)
                        .in_module(module.name())
                        .at_path(relative_path),
                ),
            }
        }

        for relative_path in module.labels() {
            let path = module.input_path(relative_path);
            let source = read_utf8(&path)?;
            match LabelSet::from_json_str(&source) {
                Ok(labels) => {
                    for rule in labels.rules() {
                        if !namespace_owns(module.namespace(), rule.kind()) {
                            diagnostics.push(
                                Diagnostic::error(
                                    "labels.namespace_violation",
                                    format!(
                                        "label kind {} is outside namespace {}",
                                        rule.kind(),
                                        module.namespace()
                                    ),
                                )
                                .in_module(module.name())
                                .at_path(relative_path),
                            );
                        }
                    }
                    label_sets.push(labels);
                }
                Err(BundleError::Validation(label_diagnostics)) => {
                    diagnostics.extend(label_diagnostics.into_iter().map(|diagnostic| {
                        diagnostic.in_module(module.name()).at_path(relative_path)
                    }));
                }
                Err(error) => return Err(error),
            }
        }

        module_record.policy_ids = module_policy_ids;
        modules.push(module_record);
    }

    let labels = match LabelSet::combine(label_sets) {
        Ok(labels) => labels,
        Err(BundleError::Validation(mut label_diagnostics)) => {
            diagnostics.append(&mut label_diagnostics);
            LabelSet::default()
        }
        Err(error) => return Err(error),
    };

    let aggregate_policy_set = aggregate_policy_set_valid.then_some(aggregate_policy_set);

    let schema_json = if has_schema {
        match Schema::from_json_value(schema_json.clone()) {
            Ok(schema) => {
                if let Some(policy_set) = &aggregate_policy_set {
                    validate_policy_set(policy_set, &schema, &mut diagnostics);
                }
                diagnostics.extend(labels.validate_schema(&schema, &schema_json));
                Some(schema_json)
            }
            Err(error) => {
                diagnostics.push(Diagnostic::error(
                    "schema.aggregate_invalid",
                    error.to_string(),
                ));
                None
            }
        }
    } else {
        diagnostics.push(Diagnostic::warning(
            "schema.compatibility_skipped",
            "policy and label schema compatibility checks were skipped because the bundle has no schema",
        ));
        None
    };

    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(BundleError::Validation(diagnostics));
    }

    Ok(BundleParts {
        name: manifest.name().to_string(),
        modules,
        policies: policy_text,
        schema_json,
        labels,
        policy_ids: policy_ids.into_iter().collect(),
        diagnostics,
    })
}

pub(crate) fn validate_archive_parts(
    name: String,
    modules: Vec<ModuleRecord>,
    policies: String,
    schema_json: Option<Value>,
    labels: LabelSet,
    declared_policy_ids: &[String],
) -> Result<BundleParts> {
    let mut diagnostics = Vec::new();
    let policy_set = policies.parse::<PolicySet>().map_err(|error| {
        BundleError::Validation(vec![Diagnostic::error("policy.syntax", error.to_string())])
    })?;
    if policy_set.num_of_templates() != 0 || policy_set.policies().any(|policy| !policy.is_static())
    {
        diagnostics.push(Diagnostic::error(
            "policy.templates_unsupported",
            "deployable bundles may contain only static policies",
        ));
    }

    let mut actual_ids = BTreeSet::new();
    let module_by_policy = modules
        .iter()
        .flat_map(|module| {
            module
                .policy_ids
                .iter()
                .map(move |policy_id| (policy_id.as_str(), module))
        })
        .collect::<BTreeMap<_, _>>();
    for policy in policy_set.policies() {
        let Some(id) = policy.annotation("id").filter(|id| !id.is_empty()) else {
            diagnostics.push(Diagnostic::error(
                "policy.missing_id",
                "every bundled policy requires a non-empty @id annotation",
            ));
            continue;
        };
        if !actual_ids.insert(id.to_string()) {
            diagnostics.push(Diagnostic::error(
                "policy.duplicate_id",
                format!("duplicate policy @id {id:?}"),
            ));
        }
        let Some(module) = module_by_policy.get(id) else {
            diagnostics.push(Diagnostic::error(
                "archive.policy_module_missing",
                format!("policy {id:?} is not assigned to a module"),
            ));
            continue;
        };
        if !id.starts_with(&format!("{}.", module.name)) {
            diagnostics.push(Diagnostic::warning(
                "policy.id_prefix",
                format!(
                    "policy @id {id:?} should start with {:?} followed by '.'",
                    module.name
                ),
            ));
        }
        validate_policy_ownership(policy, id, module, &mut diagnostics);
    }

    let declared = declared_policy_ids.iter().cloned().collect::<BTreeSet<_>>();
    if actual_ids != declared {
        diagnostics.push(Diagnostic::error(
            "archive.policy_ids_mismatch",
            "manifest policy IDs do not match policies.cedar",
        ));
    }

    if let Some(schema_json) = &schema_json {
        validate_aggregate_schema_ownership(schema_json, &modules, &mut diagnostics);
        match Schema::from_json_value(schema_json.clone()) {
            Ok(schema) => {
                validate_policy_set(&policy_set, &schema, &mut diagnostics);
                diagnostics.extend(labels.validate_schema(&schema, schema_json));
            }
            Err(error) => diagnostics.push(Diagnostic::error(
                "schema.aggregate_invalid",
                error.to_string(),
            )),
        }
    } else {
        diagnostics.push(Diagnostic::warning(
            "schema.compatibility_skipped",
            "policy and label schema compatibility checks were skipped because the bundle has no schema",
        ));
    }
    for rule in labels.rules() {
        if !modules
            .iter()
            .any(|module| namespace_owns(&module.namespace, rule.kind()))
        {
            diagnostics.push(Diagnostic::error(
                "labels.namespace_violation",
                format!("label kind {} is not owned by any module", rule.kind()),
            ));
        }
    }

    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        Err(BundleError::Validation(diagnostics))
    } else {
        Ok(BundleParts {
            name,
            modules,
            policies,
            schema_json,
            labels,
            policy_ids: actual_ids.into_iter().collect(),
            diagnostics,
        })
    }
}

fn validate_module_policies(
    policy_set: &PolicySet,
    module: &ModuleRecord,
    relative_path: &str,
    module_policy_ids: &mut Vec<String>,
    all_policy_ids: &mut BTreeSet<String>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if policy_set.num_of_templates() != 0 || policy_set.policies().any(|policy| !policy.is_static())
    {
        diagnostics.push(
            Diagnostic::error(
                "policy.templates_unsupported",
                "deployable bundles may contain only static policies",
            )
            .in_module(&module.name)
            .at_path(relative_path),
        );
    }
    for policy in policy_set.policies() {
        let Some(id) = policy.annotation("id").filter(|id| !id.is_empty()) else {
            diagnostics.push(
                Diagnostic::error(
                    "policy.missing_id",
                    "every bundled policy requires a non-empty @id annotation",
                )
                .in_module(&module.name)
                .at_path(relative_path),
            );
            continue;
        };
        if !all_policy_ids.insert(id.to_string()) {
            diagnostics.push(
                Diagnostic::error(
                    "policy.duplicate_id",
                    format!("duplicate policy @id {id:?}"),
                )
                .in_module(&module.name)
                .at_path(relative_path),
            );
        }
        module_policy_ids.push(id.to_string());
        if !id.starts_with(&format!("{}.", module.name)) {
            diagnostics.push(
                Diagnostic::warning(
                    "policy.id_prefix",
                    format!(
                        "policy @id {id:?} should start with {:?} followed by '.'",
                        module.name
                    ),
                )
                .in_module(&module.name)
                .at_path(relative_path),
            );
        }
        let start = diagnostics.len();
        validate_policy_ownership(policy, id, module, diagnostics);
        for diagnostic in &mut diagnostics[start..] {
            diagnostic.module = Some(module.name.clone());
            diagnostic.path = Some(relative_path.to_string());
        }
    }
}

fn validate_policy_ownership(
    policy: &Policy,
    policy_id: &str,
    module: &ModuleRecord,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let pst = match policy.to_pst() {
        Ok(pst) => pst,
        Err(error) => {
            diagnostics.push(Diagnostic::error(
                "policy.structured_representation",
                format!("policy {policy_id:?} cannot be represented structurally: {error}"),
            ));
            return;
        }
    };
    let body = pst.body();
    if module.role == ModuleRole::Global {
        return;
    }
    match &body.action {
        PstActionConstraint::Any => diagnostics.push(Diagnostic::error(
            "policy.action_unconstrained",
            format!("ordinary policy {policy_id:?} must constrain its actions"),
        )),
        PstActionConstraint::Eq(uid) => {
            check_owned_action(&uid.ty.to_string(), policy_id, module, diagnostics)
        }
        PstActionConstraint::In(uids) => {
            for uid in uids {
                check_owned_action(&uid.ty.to_string(), policy_id, module, diagnostics);
            }
        }
    }

    let mut references = Vec::new();
    match &body.principal {
        PstPrincipalConstraint::Any => {}
        PstPrincipalConstraint::Eq(value) | PstPrincipalConstraint::In(value) => {
            collect_entity_or_slot(value, &mut references)
        }
        PstPrincipalConstraint::Is(entity_type) => {
            references.push(entity_type.to_string());
        }
        PstPrincipalConstraint::IsIn(entity_type, value) => {
            references.push(entity_type.to_string());
            collect_entity_or_slot(value, &mut references);
        }
    }
    match &body.resource {
        PstResourceConstraint::Any => {}
        PstResourceConstraint::Eq(value) | PstResourceConstraint::In(value) => {
            collect_entity_or_slot(value, &mut references)
        }
        PstResourceConstraint::Is(entity_type) => references.push(entity_type.to_string()),
        PstResourceConstraint::IsIn(entity_type, value) => {
            references.push(entity_type.to_string());
            collect_entity_or_slot(value, &mut references);
        }
    }
    match &body.action {
        PstActionConstraint::Any => {}
        PstActionConstraint::Eq(uid) => references.push(uid.ty.to_string()),
        PstActionConstraint::In(uids) => {
            references.extend(uids.iter().map(|uid| uid.ty.to_string()));
        }
    }
    for clause in body.clauses() {
        let expression = match clause {
            Clause::When(expression) | Clause::Unless(expression) => expression,
        };
        collect_expr_references(expression, &mut references);
    }
    for reference in references {
        if !namespace_owns(&module.namespace, &reference)
            && !module
                .imports
                .iter()
                .any(|import| namespace_owns(import, &reference))
        {
            diagnostics.push(Diagnostic::error(
                "policy.namespace_violation",
                format!(
                    "policy {policy_id:?} references {reference}, outside namespace {} and its imports",
                    module.namespace
                ),
            ));
        }
    }
}

fn check_owned_action(
    entity_type: &str,
    policy_id: &str,
    module: &ModuleRecord,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if !namespace_owns(&module.namespace, entity_type) {
        diagnostics.push(Diagnostic::error(
            "policy.action_namespace_violation",
            format!(
                "ordinary policy {policy_id:?} constrains action type {entity_type} outside namespace {}",
                module.namespace
            ),
        ));
    }
}

fn collect_entity_or_slot(value: &EntityOrSlot, references: &mut Vec<String>) {
    if let EntityOrSlot::Entity(uid) = value {
        references.push(uid.ty.to_string());
    }
}

fn collect_expr_references(expression: &Expr, references: &mut Vec<String>) {
    match expression {
        Expr::Literal(Literal::EntityUID(uid)) => references.push(uid.ty.to_string()),
        Expr::UnaryOp { expr, .. }
        | Expr::GetAttr { expr, .. }
        | Expr::HasAttr { expr, .. }
        | Expr::Like { expr, .. } => collect_expr_references(expr, references),
        Expr::BinaryOp { left, right, .. } => {
            collect_expr_references(left, references);
            collect_expr_references(right, references);
        }
        Expr::Is {
            expr,
            entity_type,
            in_expr,
        } => {
            references.push(entity_type.to_string());
            collect_expr_references(expr, references);
            if let Some(in_expr) = in_expr {
                collect_expr_references(in_expr, references);
            }
        }
        Expr::IfThenElse {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_expr_references(cond, references);
            collect_expr_references(then_expr, references);
            collect_expr_references(else_expr, references);
        }
        Expr::Set(expressions) => {
            for expression in expressions {
                collect_expr_references(expression, references);
            }
        }
        Expr::Record(expressions) => {
            for expression in expressions.values() {
                collect_expr_references(expression, references);
            }
        }
        _ => {}
    }
}

fn parse_schema_fragment(
    source: &str,
) -> std::result::Result<(SchemaFragment, Vec<Diagnostic>), String> {
    let trimmed = source.trim_start();
    if trimmed.starts_with('{') {
        SchemaFragment::from_json_str(source)
            .map(|fragment| (fragment, Vec::new()))
            .map_err(|error| error.to_string())
    } else {
        SchemaFragment::from_cedarschema_str(source)
            .map(|(fragment, warnings)| {
                (
                    fragment,
                    warnings
                        .map(|warning| Diagnostic::warning("schema.warning", warning.to_string()))
                        .collect(),
                )
            })
            .map_err(|error| error.to_string())
    }
}

fn validate_policy_set(policy_set: &PolicySet, schema: &Schema, diagnostics: &mut Vec<Diagnostic>) {
    let result = Validator::new(schema.clone()).validate(policy_set, ValidationMode::Strict);
    diagnostics.extend(
        result
            .validation_errors()
            .map(|error| Diagnostic::error("policy.schema_validation", error.to_string())),
    );
    diagnostics.extend(
        result
            .validation_warnings()
            .map(|warning| Diagnostic::warning("policy.schema_warning", warning.to_string())),
    );
}

fn validate_schema_ownership(
    schema_json: &Value,
    module_name: &str,
    namespace: &str,
    relative_path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(namespaces) = schema_json.as_object() else {
        return;
    };
    for declared_namespace in namespaces.keys() {
        if !namespace_owns(namespace, declared_namespace) {
            diagnostics.push(
                Diagnostic::error(
                    "schema.namespace_violation",
                    format!(
                        "schema namespace {declared_namespace:?} is outside module namespace {namespace:?}"
                    ),
                )
                .in_module(module_name)
                .at_path(relative_path),
            );
        }
    }
}

fn validate_aggregate_schema_ownership(
    schema_json: &Value,
    modules: &[ModuleRecord],
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(namespaces) = schema_json.as_object() else {
        return;
    };
    for namespace in namespaces.keys() {
        if !modules
            .iter()
            .any(|module| namespace_owns(&module.namespace, namespace))
        {
            diagnostics.push(Diagnostic::error(
                "schema.namespace_violation",
                format!("schema namespace {namespace:?} is not owned by any module"),
            ));
        }
    }
}

fn merge_schema_fragment(
    target: &mut Value,
    fragment: Value,
    module_name: &str,
    relative_path: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(target_namespaces) = target.as_object_mut() else {
        return;
    };
    let Some(fragment_namespaces) = fragment.as_object() else {
        return;
    };
    for (namespace, definition) in fragment_namespaces {
        let target_definition = target_namespaces
            .entry(namespace.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(target_fields) = target_definition.as_object_mut() else {
            continue;
        };
        let Some(fields) = definition.as_object() else {
            continue;
        };
        for (field, value) in fields {
            if matches!(field.as_str(), "entityTypes" | "actions" | "commonTypes") {
                let target_declarations = target_fields
                    .entry(field.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                let Some(target_declarations) = target_declarations.as_object_mut() else {
                    continue;
                };
                if let Some(declarations) = value.as_object() {
                    for (name, declaration) in declarations {
                        if target_declarations
                            .insert(name.clone(), declaration.clone())
                            .is_some()
                        {
                            diagnostics.push(
                                Diagnostic::error(
                                    "schema.duplicate_declaration",
                                    format!("duplicate {field} declaration {namespace}::{name}"),
                                )
                                .in_module(module_name)
                                .at_path(relative_path),
                            );
                        }
                    }
                }
            } else if let Some(existing) = target_fields.get(field) {
                if existing != value {
                    diagnostics.push(
                        Diagnostic::error(
                            "schema.duplicate_metadata",
                            format!("conflicting schema namespace field {namespace}.{field}"),
                        )
                        .in_module(module_name)
                        .at_path(relative_path),
                    );
                }
            } else {
                target_fields.insert(field.clone(), value.clone());
            }
        }
    }
}

fn read_utf8(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|error| BundleError::io(path, error))?;
    String::from_utf8(bytes).map_err(|error| {
        BundleError::Validation(vec![
            Diagnostic::error("input.invalid_utf8", error.to_string())
                .at_path(path.display().to_string()),
        ])
    })
}

pub(crate) fn normalize_text(source: &str) -> String {
    let mut normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    while normalized.ends_with('\n') {
        normalized.pop();
    }
    normalized.push('\n');
    normalized
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character == '\r' || character == '\n' {
                ' '
            } else {
                character
            }
        })
        .collect()
}
