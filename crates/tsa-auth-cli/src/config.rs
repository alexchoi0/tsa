use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    pub server_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub contexts: HashMap<String, Context>,
}

impl CliConfig {
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("tsa")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.toml")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::config_dir();
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(Self::config_path(), content)?;
        Ok(())
    }

    pub fn current_context(&self) -> Option<&Context> {
        self.current_context
            .as_ref()
            .and_then(|name| self.contexts.get(name))
    }

    pub fn server_url(&self) -> Option<&str> {
        self.current_context().map(|c| c.server_url.as_str())
    }

    pub fn token(&self) -> Option<&str> {
        self.current_context().and_then(|c| c.token.as_deref())
    }

    pub fn set_context(
        &mut self,
        name: &str,
        server_url: String,
        token: Option<String>,
    ) -> Result<()> {
        self.contexts
            .insert(name.to_string(), Context { server_url, token });
        if self.current_context.is_none() {
            self.current_context = Some(name.to_string());
        }
        self.save()
    }

    pub fn use_context(&mut self, name: &str) -> Result<()> {
        if !self.contexts.contains_key(name) {
            return Err(anyhow!("Context '{}' not found", name));
        }
        self.current_context = Some(name.to_string());
        self.save()
    }

    pub fn delete_context(&mut self, name: &str) -> Result<()> {
        if !self.contexts.contains_key(name) {
            return Err(anyhow!("Context '{}' not found", name));
        }
        self.contexts.remove(name);
        if self.current_context.as_deref() == Some(name) {
            self.current_context = self.contexts.keys().next().cloned();
        }
        self.save()
    }

    pub fn rename_context(&mut self, old_name: &str, new_name: &str) -> Result<()> {
        let ctx = self
            .contexts
            .remove(old_name)
            .ok_or_else(|| anyhow!("Context '{}' not found", old_name))?;
        self.contexts.insert(new_name.to_string(), ctx);
        if self.current_context.as_deref() == Some(old_name) {
            self.current_context = Some(new_name.to_string());
        }
        self.save()
    }

    pub fn set_token(&mut self, token: Option<String>) -> Result<()> {
        let ctx_name = self
            .current_context
            .clone()
            .ok_or_else(|| anyhow!("No context selected. Use 'tsa config set-context' first."))?;
        if let Some(ctx) = self.contexts.get_mut(&ctx_name) {
            ctx.token = token;
        }
        self.save()
    }
}
