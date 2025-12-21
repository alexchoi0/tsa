use anyhow::Result;
use colored::Colorize;

use crate::config::CliConfig;

pub fn set_context(name: &str, server_url: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    config.set_context(name, server_url.to_string(), None)?;

    println!("{} Context '{}' created", "✓".green(), name.cyan());
    println!("  {} {}", "server_url:".dimmed(), server_url);

    Ok(())
}

pub fn use_context(name: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    config.use_context(name)?;

    println!("{} Switched to context '{}'", "✓".green(), name.cyan());

    Ok(())
}

pub fn get_contexts() -> Result<()> {
    let config = CliConfig::load()?;

    if config.contexts.is_empty() {
        println!("{}", "No contexts configured".yellow());
        println!();
        println!(
            "Create one with: {} set-context <name> --server <url>",
            "tsa config".dimmed()
        );
        return Ok(());
    }

    println!("{}", "Contexts".blue().bold());
    println!();

    for (name, ctx) in &config.contexts {
        let is_current = config.current_context.as_deref() == Some(name.as_str());
        let marker = if is_current { "*" } else { " " };
        let name_display = if is_current {
            name.green().bold().to_string()
        } else {
            name.to_string()
        };

        println!("{} {}", marker.green(), name_display);
        println!("    {} {}", "server:".dimmed(), ctx.server_url);
        println!(
            "    {} {}",
            "token:".dimmed(),
            if ctx.token.is_some() {
                "(set)".green().to_string()
            } else {
                "(not set)".yellow().to_string()
            }
        );
    }

    Ok(())
}

pub fn current_context() -> Result<()> {
    let config = CliConfig::load()?;

    match &config.current_context {
        Some(name) => println!("{}", name),
        None => println!("{}", "(none)".yellow()),
    }

    Ok(())
}

pub fn delete_context(name: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    config.delete_context(name)?;

    println!("{} Context '{}' deleted", "✓".green(), name);

    Ok(())
}

pub fn rename_context(old_name: &str, new_name: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    config.rename_context(old_name, new_name)?;

    println!(
        "{} Context '{}' renamed to '{}'",
        "✓".green(),
        old_name,
        new_name.cyan()
    );

    Ok(())
}

pub fn set_token(token: &str) -> Result<()> {
    let mut config = CliConfig::load()?;
    config.set_token(Some(token.to_string()))?;

    println!("{} Token set for current context", "✓".green());

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

    match &config.current_context {
        Some(name) => {
            println!("  {}: {}", "Current Context".cyan(), name.green().bold());
            if let Some(ctx) = config.contexts.get(name) {
                println!("  {}: {}", "Server URL".cyan(), ctx.server_url);
                println!(
                    "  {}: {}",
                    "Token".cyan(),
                    if ctx.token.is_some() {
                        "(set)".green().to_string()
                    } else {
                        "(not set)".yellow().to_string()
                    }
                );
            }
        }
        None => {
            println!("  {}: {}", "Current Context".cyan(), "(none)".yellow());
        }
    }

    if config.contexts.len() > 1 {
        println!();
        println!("  {}: {}", "Total Contexts".dimmed(), config.contexts.len());
    }

    Ok(())
}

pub fn init() -> Result<()> {
    let mut config = CliConfig::load()?;

    if config.contexts.is_empty() {
        config.set_context("default", "http://localhost:3000".to_string(), None)?;
    }

    println!("{}", "Configuration initialized!".green().bold());
    println!();
    println!("  Config file: {}", CliConfig::config_path().display());
    println!();
    println!(
        "  Run {} to add more contexts",
        "tsa config set-context".cyan()
    );

    Ok(())
}
