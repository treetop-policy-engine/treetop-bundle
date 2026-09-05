//! Explicit schema modes for engines prepared from optional-schema bundles.

use treetop_core::{
    Decision, EvaluationSession, LabelRegistry, PolicyCandidates, PolicyEngine, PolicyError,
    PolicyStoreId, PolicyVersion, Request, RequestContext, SchemaEnforcing, SchemaFree,
};

/// A prepared engine retaining the bundle's schema validation capability.
///
/// Match the variant to access mode-specific Core operations. A schema-free
/// engine cannot be represented as schema-enforcing:
///
/// ```compile_fail
/// use treetop_bundle::PreparedEngine;
/// use treetop_core::PolicyEngine;
/// let free = PolicyEngine::new_from_str("").unwrap();
/// let enforcing = PreparedEngine::SchemaEnforcing(free);
/// ```
#[derive(Clone)]
pub enum PreparedEngine {
    /// A bundle without an enforcing Cedar schema.
    SchemaFree(PolicyEngine<SchemaFree>),
    /// A bundle with a fully validated, enforcing Cedar schema.
    SchemaEnforcing(PolicyEngine<SchemaEnforcing>),
}

/// One frozen authorization generation, retaining its schema mode.
#[derive(Clone)]
pub enum PreparedEvaluationSession {
    /// A frozen generation without schema enforcement.
    SchemaFree(EvaluationSession<SchemaFree>),
    /// A frozen generation with schema enforcement.
    SchemaEnforcing(EvaluationSession<SchemaEnforcing>),
}

impl From<PolicyEngine<SchemaFree>> for PreparedEngine {
    fn from(engine: PolicyEngine<SchemaFree>) -> Self {
        Self::SchemaFree(engine)
    }
}

impl From<PolicyEngine<SchemaEnforcing>> for PreparedEngine {
    fn from(engine: PolicyEngine<SchemaEnforcing>) -> Self {
        Self::SchemaEnforcing(engine)
    }
}

impl PreparedEngine {
    /// Install a validated registry while retaining the engine's schema mode.
    pub fn with_label_registry(self, registry: LabelRegistry) -> Self {
        match self {
            Self::SchemaFree(engine) => Self::SchemaFree(engine.with_label_registry(registry)),
            Self::SchemaEnforcing(engine) => {
                Self::SchemaEnforcing(engine.with_label_registry(registry))
            }
        }
    }

    /// Capture one complete generation for all evaluations and version reporting.
    pub fn session(&self) -> PreparedEvaluationSession {
        match self {
            Self::SchemaFree(engine) => PreparedEvaluationSession::SchemaFree(engine.session()),
            Self::SchemaEnforcing(engine) => {
                PreparedEvaluationSession::SchemaEnforcing(engine.session())
            }
        }
    }
    /// Return the current complete authorization-state version.
    pub fn current_version(&self) -> PolicyVersion {
        match self {
            Self::SchemaFree(engine) => engine.current_version(),
            Self::SchemaEnforcing(engine) => engine.current_version(),
        }
    }

    /// Return configured store IDs, or None for a monolithic engine.
    pub fn policy_store_ids(&self) -> Option<Vec<PolicyStoreId>> {
        match self {
            Self::SchemaFree(engine) => engine.policy_store_ids(),
            Self::SchemaEnforcing(engine) => engine.policy_store_ids(),
        }
    }

    /// List structural permit-policy candidates; these do not authorize operations.
    ///
    /// Returns Core validation errors for malformed principal inputs.
    pub fn list_policies_for_user(
        &self,
        user: &str,
        groups: &[&str],
        namespace: &[&str],
    ) -> Result<PolicyCandidates, PolicyError> {
        match self {
            Self::SchemaFree(engine) => engine.list_policies_for_user(user, groups, namespace),
            Self::SchemaEnforcing(engine) => engine.list_policies_for_user(user, groups, namespace),
        }
    }

    /// Evaluate a request, returning Core errors for invalid request data.
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        match self {
            Self::SchemaFree(engine) => engine.evaluate(request),
            Self::SchemaEnforcing(engine) => engine.evaluate(request),
        }
    }

    /// Evaluate with explicit context, returning Core validation/evaluation errors.
    pub fn evaluate_with_context(
        &self,
        request: &Request,
        context: &RequestContext,
    ) -> Result<Decision, PolicyError> {
        match self {
            Self::SchemaFree(engine) => engine.evaluate_with_context(request, context),
            Self::SchemaEnforcing(engine) => engine.evaluate_with_context(request, context),
        }
    }
}

impl PreparedEvaluationSession {
    /// Return the exact version used by every evaluation in this session.
    pub fn version(&self) -> PolicyVersion {
        match self {
            Self::SchemaFree(engine) => engine.version(),
            Self::SchemaEnforcing(engine) => engine.version(),
        }
    }

    /// Evaluate a request, returning Core errors for invalid request data.
    pub fn evaluate(&self, request: &Request) -> Result<Decision, PolicyError> {
        match self {
            Self::SchemaFree(engine) => engine.evaluate(request),
            Self::SchemaEnforcing(engine) => engine.evaluate(request),
        }
    }

    /// Evaluate with explicit context, returning Core validation/evaluation errors.
    pub fn evaluate_with_context(
        &self,
        request: &Request,
        context: &RequestContext,
    ) -> Result<Decision, PolicyError> {
        match self {
            Self::SchemaFree(engine) => engine.evaluate_with_context(request, context),
            Self::SchemaEnforcing(engine) => engine.evaluate_with_context(request, context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use treetop_core::{Action, Principal, Resource, User};

    #[test]
    fn session_retains_policy_generation_after_reload() {
        let core = PolicyEngine::new_from_str("permit(principal, action, resource);").unwrap();
        let prepared = PreparedEngine::from(core.clone());
        let session = prepared.session();
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("read", None).unwrap(),
            resource: Resource::new("Document", "one").unwrap(),
        };
        core.reload_from_str("forbid(principal, action, resource);")
            .unwrap();
        let old = session.evaluate(&request).unwrap();
        assert!(old.is_allowed());
        assert_eq!(old.version(), &session.version());
        assert!(!prepared.evaluate(&request).unwrap().is_allowed());
        assert!(prepared.current_version().generation > session.version().generation);
    }

    #[test]
    fn schema_enforcing_variant_retains_validation() {
        let schema = r#"entity User; entity Document; action "read" appliesTo {
            principal: [User], resource: [Document], context: {}
        };"#;
        let core = PolicyEngine::new_from_str_with_cedarschema(
            "permit(principal, action, resource);",
            schema,
        )
        .unwrap();
        let prepared = PreparedEngine::from(core);
        assert!(matches!(prepared, PreparedEngine::SchemaEnforcing(_)));
        let request = Request {
            principal: Principal::User(User::new("alice", None, None).unwrap()),
            action: Action::new("unknown", None).unwrap(),
            resource: Resource::new("Document", "one").unwrap(),
        };
        assert!(prepared.session().evaluate(&request).is_err());
    }
}
