use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tsa_core::{Result, TsaError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    #[serde(default)]
    pub resources: HashMap<String, ResourceDef>,
    pub roles: HashMap<String, RoleDef>,
    #[serde(default)]
    pub approval_channels: HashMap<String, ApprovalChannelDef>,
    #[serde(default)]
    pub approval_policies: HashMap<String, ApprovalPolicyDef>,
    #[serde(default)]
    pub default_role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDef {
    pub actions: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDef {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub inherits: Option<String>,
    pub permissions: Vec<PermissionDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PermissionDef {
    Simple(String),
    WithApproval {
        permission: String,
        requires_approval: String,
    },
}

impl PermissionDef {
    pub fn permission_string(&self) -> &str {
        match self {
            PermissionDef::Simple(s) => s,
            PermissionDef::WithApproval { permission, .. } => permission,
        }
    }

    pub fn approval_policy(&self) -> Option<&str> {
        match self {
            PermissionDef::Simple(_) => None,
            PermissionDef::WithApproval { requires_approval, .. } => Some(requires_approval),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChannelDef {
    #[serde(rename = "type")]
    pub channel_type: ApprovalChannelType,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalChannelType {
    MagicLink,
    Slack,
    Webhook,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicyDef {
    #[serde(default)]
    pub description: Option<String>,
    pub approvers: ApproversDef,
    #[serde(default = "default_required")]
    pub required: u32,
    pub channels: Vec<String>,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub auto_deny_after: Option<String>,
}

fn default_required() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproversDef {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub users: Vec<String>,
}

impl RbacConfig {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let yaml = Self::interpolate_env_vars(yaml);
        serde_yaml::from_str(&yaml).map_err(|e| TsaError::Configuration(format!("Invalid RBAC YAML: {}", e)))
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| TsaError::Configuration(format!("Failed to read RBAC file: {}", e)))?;
        Self::from_yaml(&content)
    }

    fn interpolate_env_vars(yaml: &str) -> String {
        let mut result = yaml.to_string();
        let re = regex::Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}").unwrap();

        for cap in re.captures_iter(yaml) {
            let var_name = &cap[1];
            if let Ok(value) = std::env::var(var_name) {
                result = result.replace(&cap[0], &value);
            }
        }

        result
    }

    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        for (role_name, role) in &self.roles {
            if let Some(ref inherits) = role.inherits {
                if !self.roles.contains_key(inherits) {
                    errors.push(format!("Role '{}' inherits from unknown role '{}'", role_name, inherits));
                }
                if self.has_circular_inheritance(role_name, &mut HashSet::new()) {
                    errors.push(format!("Role '{}' has circular inheritance", role_name));
                }
            }

            for perm in &role.permissions {
                if let PermissionDef::WithApproval { requires_approval, .. } = perm {
                    if !self.approval_policies.contains_key(requires_approval) {
                        errors.push(format!(
                            "Role '{}' references unknown approval policy '{}'",
                            role_name, requires_approval
                        ));
                    }
                }
            }
        }

        for (policy_name, policy) in &self.approval_policies {
            for channel in &policy.channels {
                if !self.approval_channels.contains_key(channel) {
                    errors.push(format!(
                        "Approval policy '{}' references unknown channel '{}'",
                        policy_name, channel
                    ));
                }
            }

            for role in &policy.approvers.roles {
                if !self.roles.contains_key(role) {
                    errors.push(format!(
                        "Approval policy '{}' references unknown role '{}'",
                        policy_name, role
                    ));
                }
            }
        }

        if let Some(ref default) = self.default_role {
            if !self.roles.contains_key(default) {
                errors.push(format!("Default role '{}' does not exist", default));
            }
        }

        if !self.resources.is_empty() {
            for (role_name, role) in &self.roles {
                for perm in &role.permissions {
                    let perm_str = perm.permission_string();
                    if perm_str != "*" && !perm_str.ends_with(":*") {
                        if let Some((resource, action)) = perm_str.split_once(':') {
                            if let Some(res_def) = self.resources.get(resource) {
                                if !res_def.actions.contains(&action.to_string()) {
                                    errors.push(format!(
                                        "Role '{}' has permission '{}' but action '{}' is not defined for resource '{}'",
                                        role_name, perm_str, action, resource
                                    ));
                                }
                            } else {
                                errors.push(format!(
                                    "Role '{}' has permission '{}' but resource '{}' is not defined",
                                    role_name, perm_str, resource
                                ));
                            }
                        }
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(TsaError::Configuration(format!("RBAC validation errors:\n- {}", errors.join("\n- "))))
        }
    }

    fn has_circular_inheritance(&self, role: &str, visited: &mut HashSet<String>) -> bool {
        if visited.contains(role) {
            return true;
        }
        visited.insert(role.to_string());

        if let Some(role_def) = self.roles.get(role) {
            if let Some(ref inherits) = role_def.inherits {
                return self.has_circular_inheritance(inherits, visited);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_config() {
        let yaml = r#"
roles:
  viewer:
    permissions:
      - resources:read
  admin:
    inherits: viewer
    permissions:
      - resources:write
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.roles.len(), 2);
        assert!(config.roles.contains_key("viewer"));
        assert!(config.roles.contains_key("admin"));
    }

    #[test]
    fn test_parse_with_approval() {
        let yaml = r#"
approval_channels:
  magic_link:
    type: magic_link
    expiry: 24h

approval_policies:
  admin_approval:
    approvers:
      roles: [admin]
    required: 1
    channels: [magic_link]

roles:
  admin:
    permissions:
      - billing:read
      - permission: billing:update
        requires_approval: admin_approval
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn test_circular_inheritance_detected() {
        let yaml = r#"
roles:
  a:
    inherits: b
    permissions: []
  b:
    inherits: a
    permissions: []
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_env_var_interpolation() {
        std::env::set_var("TEST_WEBHOOK_URL", "https://hooks.example.com/test");
        let yaml = r#"
approval_channels:
  slack:
    type: slack
    webhook_url: ${TEST_WEBHOOK_URL}

approval_policies:
  test:
    approvers:
      roles: [admin]
    required: 1
    channels: [slack]

roles:
  admin:
    permissions:
      - test:read
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        assert_eq!(
            config.approval_channels.get("slack").unwrap().webhook_url,
            Some("https://hooks.example.com/test".to_string())
        );
        std::env::remove_var("TEST_WEBHOOK_URL");
    }

    #[test]
    fn test_resource_validation() {
        let yaml = r#"
resources:
  billing:
    actions: [read, update]
    description: Billing resources

roles:
  admin:
    permissions:
      - billing:delete
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("action 'delete' is not defined"));
    }
}
