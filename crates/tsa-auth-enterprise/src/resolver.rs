use std::collections::{HashMap, HashSet};
use tsa_auth_core::Result;

use crate::RbacConfig;

#[derive(Debug, Clone)]
pub struct PermissionCheck {
    pub allowed: bool,
    pub requires_approval: Option<String>,
}

pub struct RbacResolver {
    config: RbacConfig,
    resolved_permissions: HashMap<String, HashSet<String>>,
}

impl RbacResolver {
    pub fn new(config: RbacConfig) -> Result<Self> {
        config.validate()?;

        let resolved_permissions = Self::resolve_all_permissions(&config);

        Ok(Self {
            config,
            resolved_permissions,
        })
    }

    fn resolve_all_permissions(config: &RbacConfig) -> HashMap<String, HashSet<String>> {
        let mut resolved: HashMap<String, HashSet<String>> = HashMap::new();

        for role in config.roles.keys() {
            Self::resolve_role_recursive(config, role, &mut resolved, &mut HashSet::new());
        }

        resolved
    }

    fn resolve_role_recursive(
        config: &RbacConfig,
        role: &str,
        resolved: &mut HashMap<String, HashSet<String>>,
        visiting: &mut HashSet<String>,
    ) -> HashSet<String> {
        if let Some(cached) = resolved.get(role) {
            return cached.clone();
        }

        if visiting.contains(role) {
            return HashSet::new();
        }
        visiting.insert(role.to_string());

        let mut permissions = HashSet::new();

        if let Some(role_def) = config.roles.get(role) {
            if let Some(ref inherits) = role_def.inherits {
                let inherited = Self::resolve_role_recursive(config, inherits, resolved, visiting);
                permissions.extend(inherited);
            }

            for perm in &role_def.permissions {
                permissions.insert(perm.permission_string().to_string());
            }
        }

        resolved.insert(role.to_string(), permissions.clone());
        permissions
    }

    pub fn check_permission(&self, role: &str, permission: &str) -> PermissionCheck {
        let permissions = match self.resolved_permissions.get(role) {
            Some(p) => p,
            None => {
                return PermissionCheck {
                    allowed: false,
                    requires_approval: None,
                }
            }
        };

        if permissions.contains("*") {
            return PermissionCheck {
                allowed: true,
                requires_approval: None,
            };
        }

        if permissions.contains(permission) {
            let approval = self.get_approval_requirement(role, permission);
            return PermissionCheck {
                allowed: true,
                requires_approval: approval,
            };
        }

        if let Some((resource, _)) = permission.split_once(':') {
            let wildcard = format!("{}:*", resource);
            if permissions.contains(&wildcard) {
                return PermissionCheck {
                    allowed: true,
                    requires_approval: None,
                };
            }
        }

        PermissionCheck {
            allowed: false,
            requires_approval: None,
        }
    }

    fn get_approval_requirement(&self, role: &str, permission: &str) -> Option<String> {
        fn find_in_role(config: &RbacConfig, role: &str, permission: &str) -> Option<String> {
            if let Some(role_def) = config.roles.get(role) {
                for perm in &role_def.permissions {
                    if perm.permission_string() == permission {
                        if let Some(policy) = perm.approval_policy() {
                            return Some(policy.to_string());
                        }
                    }
                }

                if let Some(ref inherits) = role_def.inherits {
                    return find_in_role(config, inherits, permission);
                }
            }
            None
        }

        find_in_role(&self.config, role, permission)
    }

    pub fn has_permission(&self, role: &str, permission: &str) -> bool {
        self.check_permission(role, permission).allowed
    }

    pub fn get_all_permissions(&self, role: &str) -> Vec<String> {
        self.resolved_permissions
            .get(role)
            .map(|p| p.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_roles(&self) -> Vec<&str> {
        self.config.roles.keys().map(|s| s.as_str()).collect()
    }

    pub fn get_default_role(&self) -> Option<&str> {
        self.config.default_role.as_deref()
    }

    pub fn get_approval_policy(&self, policy_name: &str) -> Option<&crate::ApprovalPolicyDef> {
        self.config.approval_policies.get(policy_name)
    }

    pub fn get_approval_channel(&self, channel_name: &str) -> Option<&crate::ApprovalChannelDef> {
        self.config.approval_channels.get(channel_name)
    }

    pub fn config(&self) -> &RbacConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RbacConfig {
        let yaml = r#"
roles:
  viewer:
    permissions:
      - resources:read
      - projects:read

  editor:
    inherits: viewer
    permissions:
      - resources:write
      - projects:*

  admin:
    inherits: editor
    permissions:
      - users:*
      - billing:read
"#;
        RbacConfig::from_yaml(yaml).unwrap()
    }

    #[test]
    fn test_direct_permission() {
        let resolver = RbacResolver::new(test_config()).unwrap();
        assert!(resolver.has_permission("viewer", "resources:read"));
        assert!(!resolver.has_permission("viewer", "resources:write"));
    }

    #[test]
    fn test_inherited_permission() {
        let resolver = RbacResolver::new(test_config()).unwrap();
        assert!(resolver.has_permission("editor", "resources:read"));
        assert!(resolver.has_permission("admin", "resources:read"));
    }

    #[test]
    fn test_wildcard_permission() {
        let resolver = RbacResolver::new(test_config()).unwrap();
        assert!(resolver.has_permission("editor", "projects:delete"));
        assert!(resolver.has_permission("admin", "users:anything"));
    }

    #[test]
    fn test_permission_with_approval() {
        let yaml = r#"
approval_channels:
  magic_link:
    type: magic_link

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
        let resolver = RbacResolver::new(config).unwrap();

        let check = resolver.check_permission("admin", "billing:read");
        assert!(check.allowed);
        assert!(check.requires_approval.is_none());

        let check = resolver.check_permission("admin", "billing:update");
        assert!(check.allowed);
        assert_eq!(check.requires_approval, Some("admin_approval".to_string()));
    }

    #[test]
    fn test_unknown_role() {
        let resolver = RbacResolver::new(test_config()).unwrap();
        assert!(!resolver.has_permission("unknown", "resources:read"));
    }

    #[test]
    fn test_get_all_permissions() {
        let resolver = RbacResolver::new(test_config()).unwrap();
        let perms = resolver.get_all_permissions("editor");
        assert!(perms.contains(&"resources:read".to_string()));
        assert!(perms.contains(&"resources:write".to_string()));
        assert!(perms.contains(&"projects:*".to_string()));
    }

    #[test]
    fn test_superuser_permission() {
        let yaml = r#"
roles:
  superuser:
    permissions:
      - "*"
"#;
        let config = RbacConfig::from_yaml(yaml).unwrap();
        let resolver = RbacResolver::new(config).unwrap();
        assert!(resolver.has_permission("superuser", "anything:at:all"));
    }
}
