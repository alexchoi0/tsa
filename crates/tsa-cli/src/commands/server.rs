use anyhow::Result;
use colored::Colorize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run(host: String, port: u16) -> Result<()> {
    println!("{}", "Starting TSA server...".blue().bold());
    println!();

    std::env::set_var("TSA_HOST", &host);
    std::env::set_var("TSA_PORT", port.to_string());

    let config = tsa_axum::config::ServerConfig::from_env()?;
    let state = tsa_axum::state::AppState::new(config.clone()).await?;
    let app = tsa_axum::routes::create_router(Arc::new(state));

    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    println!("  {} {}", "Server:".green(), format!("http://{}", addr).cyan());
    println!("  {} {}", "API:".green(), format!("http://{}/api/v1", addr).cyan());
    println!("  {} {}", "Health:".green(), format!("http://{}/health", addr).cyan());
    println!();
    println!("{}", "Press Ctrl+C to stop".dimmed());
    println!();

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
