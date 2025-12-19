use anyhow::{anyhow, Result};
use colored::Colorize;

use crate::config::CliConfig;

pub fn set(key: &str, value: &str) -> Result<()> {
    let mut config = CliConfig::load()?;

    match key {
        "server_url" => {
            config.set_server_url(value.to_string())?;
            println!("{} set to {}", "server_url".cyan(), value.green());
        }
        "token" => {
            config.set_token(Some(value.to_string()))?;
            println!("{} set", "token".cyan());
        }
        _ => {
            return Err(anyhow!("Unknown config key: {}", key));
        }
    }

    Ok(())
}

pub fn get(key: &str) -> Result<()> {
    let config = CliConfig::load()?;

    match key {
        "server_url" => {
            let value = config.server_url.as_deref().unwrap_or("(not set)");
            println!("{}: {}", "server_url".cyan(), value);
        }
        "token" => {
            if config.token.is_some() {
                println!("{}: {}", "token".cyan(), "(set)".green());
            } else {
                println!("{}: {}", "token".cyan(), "(not set)".yellow());
            }
        }
        _ => {
            return Err(anyhow!("Unknown config key: {}", key));
        }
    }

    Ok(())
}

pub fn show() -> Result<()> {
    let config = CliConfig::load()?;

    println!("{}", "TSA CLI Configuration".blue().bold());
    println!();
    println!(
        "  {}: {}",
        "Config Path".dimmed(),
        CliConfig::config_path().display()
    );
    println!();
    println!(
        "  {}: {}",
        "server_url".cyan(),
        config
            .server_url
            .as_deref()
            .unwrap_or("(not set)")
    );
    println!(
        "  {}: {}",
        "token".cyan(),
        if config.token.is_some() {
            "(set)".green().to_string()
        } else {
            "(not set)".yellow().to_string()
        }
    );

    Ok(())
}

pub fn init() -> Result<()> {
    let config = CliConfig::default();
    config.save()?;

    println!("{}", "Configuration initialized!".green().bold());
    println!();
    println!(
        "  Config file created at: {}",
        CliConfig::config_path().display()
    );

    Ok(())
}
