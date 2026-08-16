use crate::{BundleError, Diagnostic, FORMAT_VERSION, Result};
use cedar_policy::EntityTypeName;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

fn default_vec<T>() -> Vec<T> {
    Vec::new()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModuleManifest {
    format_version: u32,
    name: String,
    namespace: String,
    #[serde(default = "default_vec")]
    imports: Vec<String>,
    #[serde(default = "default_vec")]
    policies: Vec<String>,
    #[serde(default = "default_vec")]
    schemas: Vec<String>,
    #[serde(default = "default_vec")]
    labels: Vec<String>,
}

/// A validated project-level source manifest.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleManifest {
    format_version: u32,
    name: String,
    namespace: String,
    imports: Vec<String>,
    policies: Vec<String>,
    schemas: Vec<String>,
    labels: Vec<String>,
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip)]
    directory: PathBuf,
}

impl ModuleManifest {
    /// Load a module manifest and resolve all inputs without allowing escapes.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let requested_path = path.as_ref();
        let bytes =
            fs::read(requested_path).map_err(|error| BundleError::io(requested_path, error))?;
        let source = std::str::from_utf8(&bytes).map_err(|error| BundleError::Manifest {
            path: requested_path.to_path_buf(),
            message: error.to_string(),
        })?;
        let raw: RawModuleManifest =
            toml::from_str(source).map_err(|error| BundleError::Manifest {
                path: requested_path.to_path_buf(),
                message: error.to_string(),
            })?;

        let path = requested_path
            .canonicalize()
            .map_err(|error| BundleError::io(requested_path, error))?;
        let directory = path.parent().map(Path::to_path_buf).ok_or_else(|| {
            BundleError::Validation(vec![Diagnostic::error(
                "manifest.no_parent",
                "module manifest must have a parent directory",
            )])
        })?;

        let mut diagnostics = Vec::new();
        if raw.format_version != FORMAT_VERSION {
            diagnostics.push(Diagnostic::error(
                "manifest.unsupported_version",
                format!(
                    "module format_version {} is unsupported; expected {FORMAT_VERSION}",
                    raw.format_version
                ),
            ));
        }
        if raw.name.trim().is_empty() {
            diagnostics.push(Diagnostic::error(
                "manifest.empty_name",
                "module name must not be empty",
            ));
        }
        validate_namespace("module namespace", &raw.namespace, &mut diagnostics);
        let mut imports = HashSet::new();
        for import in &raw.imports {
            validate_namespace("module import", import, &mut diagnostics);
            if !imports.insert(import) {
                diagnostics.push(Diagnostic::error(
                    "manifest.duplicate_import",
                    format!("duplicate import {import:?}"),
                ));
            }
        }
        if raw.imports.iter().any(|import| import == &raw.namespace) {
            diagnostics.push(Diagnostic::error(
                "manifest.self_import",
                "a module cannot import its own namespace",
            ));
        }

        for input in raw.policies.iter().chain(&raw.schemas).chain(&raw.labels) {
            validate_input_path(&directory, input, &mut diagnostics);
        }

        if diagnostics.is_empty() {
            Ok(Self {
                format_version: raw.format_version,
                name: raw.name,
                namespace: raw.namespace,
                imports: raw.imports,
                policies: raw.policies,
                schemas: raw.schemas,
                labels: raw.labels,
                path,
                directory,
            })
        } else {
            Err(BundleError::Validation(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| {
                        diagnostic
                            .in_module(raw.name.clone())
                            .at_path(requested_path.display().to_string())
                    })
                    .collect(),
            ))
        }
    }

    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn imports(&self) -> &[String] {
        &self.imports
    }

    pub fn policies(&self) -> &[String] {
        &self.policies
    }

    pub fn schemas(&self) -> &[String] {
        &self.schemas
    }

    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn input_path(&self, relative: &str) -> PathBuf {
        self.directory.join(relative)
    }
}

/// Module policy scope selected by the organization bundle manifest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleRole {
    #[default]
    Ordinary,
    Global,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawModuleSelection {
    manifest: String,
    #[serde(default)]
    role: ModuleRole,
}

/// A module selected by a bundle manifest.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleSelection {
    manifest: ModuleManifest,
    role: ModuleRole,
}

impl ModuleSelection {
    pub fn manifest(&self) -> &ModuleManifest {
        &self.manifest
    }

    pub fn role(&self) -> ModuleRole {
        self.role
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBundleManifest {
    format_version: u32,
    name: String,
    modules: Vec<RawModuleSelection>,
}

/// A validated organization-level source manifest.
#[derive(Debug, Clone, Serialize)]
pub struct BundleManifest {
    format_version: u32,
    name: String,
    modules: Vec<ModuleSelection>,
    #[serde(skip)]
    path: PathBuf,
}

impl BundleManifest {
    /// Load the root manifest and every selected module manifest.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let requested_path = path.as_ref();
        let bytes =
            fs::read(requested_path).map_err(|error| BundleError::io(requested_path, error))?;
        let source = std::str::from_utf8(&bytes).map_err(|error| BundleError::Manifest {
            path: requested_path.to_path_buf(),
            message: error.to_string(),
        })?;
        let raw: RawBundleManifest =
            toml::from_str(source).map_err(|error| BundleError::Manifest {
                path: requested_path.to_path_buf(),
                message: error.to_string(),
            })?;
        let path = requested_path
            .canonicalize()
            .map_err(|error| BundleError::io(requested_path, error))?;
        let directory = path.parent().ok_or_else(|| {
            BundleError::Validation(vec![Diagnostic::error(
                "manifest.no_parent",
                "bundle manifest must have a parent directory",
            )])
        })?;

        let mut diagnostics = Vec::new();
        if raw.format_version != FORMAT_VERSION {
            diagnostics.push(Diagnostic::error(
                "manifest.unsupported_version",
                format!(
                    "bundle format_version {} is unsupported; expected {FORMAT_VERSION}",
                    raw.format_version
                ),
            ));
        }
        if raw.name.trim().is_empty() {
            diagnostics.push(Diagnostic::error(
                "manifest.empty_name",
                "bundle name must not be empty",
            ));
        }
        if raw.modules.is_empty() {
            diagnostics.push(Diagnostic::error(
                "manifest.empty_modules",
                "bundle must select at least one module",
            ));
        }

        let mut modules = Vec::with_capacity(raw.modules.len());
        for selected in raw.modules {
            let selected_path = Path::new(&selected.manifest);
            if selected_path.is_absolute() {
                diagnostics.push(Diagnostic::error(
                    "manifest.absolute_module_path",
                    format!(
                        "module manifest path {:?} must be relative",
                        selected.manifest
                    ),
                ));
                continue;
            }
            match ModuleManifest::from_path(directory.join(selected_path)) {
                Ok(manifest) => modules.push(ModuleSelection {
                    manifest,
                    role: selected.role,
                }),
                Err(BundleError::Validation(mut nested)) => diagnostics.append(&mut nested),
                Err(error) => return Err(error),
            }
        }

        validate_module_set(&modules, &mut diagnostics);
        if diagnostics.is_empty() {
            modules.sort_by(|left, right| left.manifest.name.cmp(&right.manifest.name));
            Ok(Self {
                format_version: raw.format_version,
                name: raw.name,
                modules,
                path,
            })
        } else {
            Err(BundleError::Validation(diagnostics))
        }
    }

    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn modules(&self) -> &[ModuleSelection] {
        &self.modules
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn for_single_module(module: ModuleManifest) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            name: module.name.clone(),
            path: module.path.clone(),
            modules: vec![ModuleSelection {
                manifest: module,
                role: ModuleRole::Ordinary,
            }],
        }
    }
}

fn validate_namespace(label: &str, value: &str, diagnostics: &mut Vec<Diagnostic>) {
    if value.trim().is_empty() {
        diagnostics.push(Diagnostic::error(
            "manifest.empty_namespace",
            format!("{label} must not be empty"),
        ));
    } else if value.parse::<EntityTypeName>().is_err() {
        diagnostics.push(Diagnostic::error(
            "manifest.invalid_namespace",
            format!("{label} {value:?} is not a valid Cedar name"),
        ));
    }
}

fn validate_input_path(directory: &Path, input: &str, diagnostics: &mut Vec<Diagnostic>) {
    let input_path = Path::new(input);
    if input.is_empty()
        || input_path.is_absolute()
        || input_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || input.contains(['*', '?', '[', ']'])
    {
        diagnostics.push(Diagnostic::error(
            "manifest.invalid_input_path",
            format!("module input path {input:?} must be an explicit relative path"),
        ));
        return;
    }

    let full_path = directory.join(input_path);
    match full_path.canonicalize() {
        Ok(canonical) if canonical.starts_with(directory) && canonical.is_file() => {}
        Ok(_) => diagnostics.push(Diagnostic::error(
            "manifest.input_escape",
            format!("module input path {input:?} escapes the module directory"),
        )),
        Err(error) => diagnostics.push(Diagnostic::error(
            "manifest.input_unreadable",
            format!("module input path {input:?} cannot be resolved: {error}"),
        )),
    }
}

fn validate_module_set(modules: &[ModuleSelection], diagnostics: &mut Vec<Diagnostic>) {
    let mut names = HashSet::with_capacity(modules.len());
    for module in modules {
        if !names.insert(module.manifest.name.as_str()) {
            diagnostics.push(Diagnostic::error(
                "manifest.duplicate_module_name",
                format!("duplicate module name {:?}", module.manifest.name),
            ));
        }
    }

    let mut ordered_namespaces = modules
        .iter()
        .map(|module| module.manifest.namespace.as_str())
        .collect::<Vec<_>>();
    ordered_namespaces.sort_unstable();
    for pair in ordered_namespaces.windows(2) {
        if namespaces_overlap(pair[0], pair[1]) {
            diagnostics.push(Diagnostic::error(
                "manifest.overlapping_namespaces",
                format!(
                    "module namespace roots {:?} and {:?} overlap",
                    pair[0], pair[1]
                ),
            ));
        }
    }

    let namespaces = modules
        .iter()
        .map(|module| module.manifest.namespace.as_str())
        .collect::<HashSet<_>>();
    for module in modules {
        for import in &module.manifest.imports {
            if !namespaces.contains(import.as_str()) {
                diagnostics.push(
                    Diagnostic::error(
                        "manifest.unresolved_import",
                        format!("import {import:?} does not exactly match a selected module"),
                    )
                    .in_module(module.manifest.name.clone()),
                );
            }
        }
    }
}

pub(crate) fn namespace_owns(root: &str, name: &str) -> bool {
    name == root
        || name
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with("::"))
}

fn namespaces_overlap(left: &str, right: &str) -> bool {
    namespace_owns(left, right) || namespace_owns(right, left)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_prefixes_are_segment_aware() {
        assert!(namespaces_overlap("A::B", "A::B::C"));
        assert!(!namespaces_overlap("A::B", "A::Bee"));
    }
}
