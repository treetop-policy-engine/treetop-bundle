use treetop_bundle::{DiagnosticSeverity, check_policy};

const SCHEMA: &str = r#"
    entity User;
    entity Service;
    entity Document;
    action "read" appliesTo {
        principal: User,
        resource: Document,
    };
"#;

#[test]
fn invalid_action_application_is_an_error_without_deny_warnings() {
    let policy = r#"permit (
        principal is Service,
        action == Action::"read",
        resource is Document
    );"#;
    let checked = check_policy(policy, Some(SCHEMA), None).unwrap();

    assert!(!checked.is_valid(false));
    assert!(checked.diagnostics().iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Error
            && diagnostic.code == "policy.schema_validation"
    }));
}

#[test]
fn other_schema_warnings_remain_nonfatal_unless_denied() {
    let checked = check_policy(
        "permit(principal, action, resource) when { false };",
        Some(SCHEMA),
        None,
    )
    .unwrap();

    assert!(checked.is_valid(false));
    assert!(!checked.is_valid(true));
    assert!(checked.diagnostics().iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Warning
            && diagnostic.code == "policy.schema_warning"
    }));
}
