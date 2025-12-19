use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;
mod config;
mod client;

#[derive(Parser)]
#[command(name = "tsa")]
#[command(author, version, about = "TSA - Tokens, Sessions, Authentication CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, env = "TSA_SERVER_URL", default_value = "http://localhost:3000")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Start the TSA server")]
    Server {
        #[arg(short, long, default_value = "3000", env = "TSA_PORT")]
        port: u16,

        #[arg(short = 'H', long, default_value = "0.0.0.0", env = "TSA_HOST")]
        host: String,
    },

    #[command(about = "Authentication commands")]
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    #[command(about = "User management commands")]
    User {
        #[command(subcommand)]
        command: UserCommands,
    },

    #[command(about = "Organization management commands")]
    Org {
        #[command(subcommand)]
        command: OrgCommands,
    },

    #[command(about = "Session management commands")]
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },

    #[command(about = "API key management commands")]
    ApiKey {
        #[command(subcommand)]
        command: ApiKeyCommands,
    },

    #[command(about = "Configure CLI settings")]
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    #[command(about = "Check server health")]
    Health,
}

#[derive(Subcommand)]
enum AuthCommands {
    #[command(about = "Sign up a new user")]
    Signup {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        name: Option<String>,
    },

    #[command(about = "Sign in an existing user")]
    Signin {
        #[arg(short, long)]
        email: String,
        #[arg(short, long)]
        password: String,
    },

    #[command(about = "Sign out the current user")]
    Signout,

    #[command(about = "Show current authentication status")]
    Status,
}

#[derive(Subcommand)]
enum UserCommands {
    #[command(about = "Get current user info")]
    Me,

    #[command(about = "Update user profile")]
    Update {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        phone: Option<String>,
    },

    #[command(about = "Change password")]
    Password {
        #[arg(long)]
        current: String,
        #[arg(long)]
        new: String,
    },
}

#[derive(Subcommand)]
enum OrgCommands {
    #[command(about = "List organizations")]
    List,

    #[command(about = "Create a new organization")]
    Create {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        slug: String,
    },

    #[command(about = "Get organization details")]
    Get {
        #[arg(help = "Organization slug")]
        slug: String,
    },

    #[command(about = "Delete an organization")]
    Delete {
        #[arg(help = "Organization ID")]
        id: String,
    },

    #[command(about = "List organization members")]
    Members {
        #[arg(help = "Organization ID")]
        id: String,
    },

    #[command(about = "Add a member to an organization")]
    AddMember {
        #[arg(help = "Organization ID")]
        org_id: String,
        #[arg(help = "User ID to add")]
        user_id: String,
        #[arg(short, long, default_value = "member")]
        role: String,
    },

    #[command(about = "Remove a member from an organization")]
    RemoveMember {
        #[arg(help = "Organization ID")]
        org_id: String,
        #[arg(help = "User ID to remove")]
        user_id: String,
    },
}

#[derive(Subcommand)]
enum SessionCommands {
    #[command(about = "List active sessions")]
    List,

    #[command(about = "Revoke a session")]
    Revoke {
        #[arg(help = "Session ID")]
        id: String,
    },

    #[command(about = "Revoke all other sessions")]
    RevokeAll,
}

#[derive(Subcommand)]
enum ApiKeyCommands {
    #[command(about = "List API keys")]
    List,

    #[command(about = "Create a new API key")]
    Create {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        scopes: Option<Vec<String>>,
        #[arg(short, long)]
        expires_days: Option<i64>,
    },

    #[command(about = "Delete an API key")]
    Delete {
        #[arg(help = "API key ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    #[command(about = "Set a configuration value")]
    Set {
        key: String,
        value: String,
    },

    #[command(about = "Get a configuration value")]
    Get {
        key: String,
    },

    #[command(about = "Show all configuration")]
    Show,

    #[command(about = "Initialize configuration")]
    Init,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tsa_cli=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = config::CliConfig::load()?;

    match cli.command {
        Commands::Server { port, host } => {
            commands::server::run(host, port).await?;
        }
        Commands::Auth { command } => {
            let client = client::TsaClient::new(&cli.server, config.token.as_deref());
            match command {
                AuthCommands::Signup { email, password, name } => {
                    commands::auth::signup(&client, &email, &password, name.as_deref()).await?;
                }
                AuthCommands::Signin { email, password } => {
                    commands::auth::signin(&client, &email, &password).await?;
                }
                AuthCommands::Signout => {
                    commands::auth::signout(&client).await?;
                }
                AuthCommands::Status => {
                    commands::auth::status(&client).await?;
                }
            }
        }
        Commands::User { command } => {
            let client = client::TsaClient::new(&cli.server, config.token.as_deref());
            match command {
                UserCommands::Me => {
                    commands::user::me(&client).await?;
                }
                UserCommands::Update { name, phone } => {
                    commands::user::update(&client, name.as_deref(), phone.as_deref()).await?;
                }
                UserCommands::Password { current, new } => {
                    commands::user::change_password(&client, &current, &new).await?;
                }
            }
        }
        Commands::Org { command } => {
            let client = client::TsaClient::new(&cli.server, config.token.as_deref());
            match command {
                OrgCommands::List => {
                    commands::org::list(&client).await?;
                }
                OrgCommands::Create { name, slug } => {
                    commands::org::create(&client, &name, &slug).await?;
                }
                OrgCommands::Get { slug } => {
                    commands::org::get(&client, &slug).await?;
                }
                OrgCommands::Delete { id } => {
                    commands::org::delete(&client, &id).await?;
                }
                OrgCommands::Members { id } => {
                    commands::org::members(&client, &id).await?;
                }
                OrgCommands::AddMember { org_id, user_id, role } => {
                    commands::org::add_member(&client, &org_id, &user_id, &role).await?;
                }
                OrgCommands::RemoveMember { org_id, user_id } => {
                    commands::org::remove_member(&client, &org_id, &user_id).await?;
                }
            }
        }
        Commands::Session { command } => {
            let client = client::TsaClient::new(&cli.server, config.token.as_deref());
            match command {
                SessionCommands::List => {
                    commands::session::list(&client).await?;
                }
                SessionCommands::Revoke { id } => {
                    commands::session::revoke(&client, &id).await?;
                }
                SessionCommands::RevokeAll => {
                    commands::session::revoke_all(&client).await?;
                }
            }
        }
        Commands::ApiKey { command } => {
            let client = client::TsaClient::new(&cli.server, config.token.as_deref());
            match command {
                ApiKeyCommands::List => {
                    commands::apikey::list(&client).await?;
                }
                ApiKeyCommands::Create { name, scopes, expires_days } => {
                    commands::apikey::create(&client, &name, scopes, expires_days).await?;
                }
                ApiKeyCommands::Delete { id } => {
                    commands::apikey::delete(&client, &id).await?;
                }
            }
        }
        Commands::Config { command } => {
            match command {
                ConfigCommands::Set { key, value } => {
                    commands::config::set(&key, &value)?;
                }
                ConfigCommands::Get { key } => {
                    commands::config::get(&key)?;
                }
                ConfigCommands::Show => {
                    commands::config::show()?;
                }
                ConfigCommands::Init => {
                    commands::config::init()?;
                }
            }
        }
        Commands::Health => {
            let client = client::TsaClient::new(&cli.server, None);
            commands::health::check(&client).await?;
        }
    }

    Ok(())
}
