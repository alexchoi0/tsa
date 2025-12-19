use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    pub server_url: Option<String>,
    pub token: Option<String>,
}

impl CliConfig {
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("tsa")
    }

    pub fn config_path() -> PathBuf {
        Self::config_dir().join("config.json")
    }

    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = Self::config_dir();
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let content = serde_json::to_string_pretty(self)?;
        fs::write(Self::config_path(), content)?;
        Ok(())
    }

    pub fn set_token(&mut self, token: Option<String>) -> Result<()> {
        self.token = token;
        self.save()
    }

    pub fn set_server_url(&mut self, url: String) -> Result<()> {
        self.server_url = Some(url);
        self.save()
    }
}
