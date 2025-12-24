use clap::{Parser, Subcommand};

mod client;
mod commands;
mod config;

#[derive(Parser)]
#[command(name = "tsa")]
#[command(author, version, about = "TSA - Tokens, Sessions, Authentication CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 'c', long, global = true, env = "TSA_CONTEXT")]
    context: Option<String>,

    #[arg(long, global = true, help = "Skip TLS verification (insecure)")]
    insecure: bool,
}

#[derive(Subcommand)]
enum Commands {
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

    #[command(about = "Configure CLI settings and contexts")]
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

    #[command(about = "Update an organization")]
    Update {
        #[arg(help = "Organization ID")]
        id: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        logo: Option<String>,
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

    #[command(about = "Update a member's role")]
    UpdateMember {
        #[arg(help = "Organization ID")]
        org_id: String,
        #[arg(help = "User ID to update")]
        user_id: String,
        #[arg(short, long)]
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

    #[command(about = "Update an API key")]
    Update {
        #[arg(help = "API key ID")]
        id: String,
        #[arg(short, long)]
        name: Option<String>,
        #[arg(short, long)]
        scopes: Option<Vec<String>>,
    },

    #[command(about = "Delete an API key")]
    Delete {
        #[arg(help = "API key ID")]
        id: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    #[command(about = "Create or update a context")]
    SetContext {
        #[arg(help = "Context name")]
        name: String,
        #[arg(short, long, help = "Server URL (e.g., http://localhost:50051)")]
        server: String,
        #[arg(long, help = "Skip TLS verification for this context")]
        insecure: bool,
    },

    #[command(about = "Switch to a context")]
    UseContext {
        #[arg(help = "Context name")]
        name: String,
    },

    #[command(about = "List all contexts")]
    GetContexts,

    #[command(about = "Show current context name")]
    CurrentContext,

    #[command(about = "Delete a context")]
    DeleteContext {
        #[arg(help = "Context name")]
        name: String,
    },

    #[command(about = "Rename a context")]
    RenameContext {
        #[arg(help = "Old context name")]
        old_name: String,
        #[arg(help = "New context name")]
        new_name: String,
    },

    #[command(about = "Set auth token for current context")]
    SetToken {
        #[arg(help = "Authentication token")]
        token: String,
    },

    #[command(about = "Show all configuration")]
    Show,

    #[command(about = "Initialize configuration with default context")]
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
    let mut cfg = config::CliConfig::load()?;

    if let Some(ctx_name) = &cli.context {
        cfg.use_context(ctx_name)?;
    }

    let server_url = cfg.server_url().unwrap_or("http://localhost:50051");
    let token = cfg.token();
    let insecure = cli.insecure || cfg.is_insecure();

    match cli.command {
        Commands::Auth { command } => {
            let client = client::TsaClient::new(server_url, token, insecure);
            match command {
                AuthCommands::Signup {
                    email,
                    password,
                    name,
                } => {
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
            let client = client::TsaClient::new(server_url, token, insecure);
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
            let client = client::TsaClient::new(server_url, token, insecure);
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
                OrgCommands::Update { id, name, logo } => {
                    commands::org::update(&client, &id, name.as_deref(), logo.as_deref()).await?;
                }
                OrgCommands::Delete { id } => {
                    commands::org::delete(&client, &id).await?;
                }
                OrgCommands::Members { id } => {
                    commands::org::members(&client, &id).await?;
                }
                OrgCommands::AddMember {
                    org_id,
                    user_id,
                    role,
                } => {
                    commands::org::add_member(&client, &org_id, &user_id, &role).await?;
                }
                OrgCommands::UpdateMember {
                    org_id,
                    user_id,
                    role,
                } => {
                    commands::org::update_member(&client, &org_id, &user_id, &role).await?;
                }
                OrgCommands::RemoveMember { org_id, user_id } => {
                    commands::org::remove_member(&client, &org_id, &user_id).await?;
                }
            }
        }
        Commands::Session { command } => {
            let client = client::TsaClient::new(server_url, token, insecure);
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
            let client = client::TsaClient::new(server_url, token, insecure);
            match command {
                ApiKeyCommands::List => {
                    commands::apikey::list(&client).await?;
                }
                ApiKeyCommands::Create {
                    name,
                    scopes,
                    expires_days,
                } => {
                    commands::apikey::create(&client, &name, scopes, expires_days).await?;
                }
                ApiKeyCommands::Update { id, name, scopes } => {
                    commands::apikey::update(&client, &id, name, scopes).await?;
                }
                ApiKeyCommands::Delete { id } => {
                    commands::apikey::delete(&client, &id).await?;
                }
            }
        }
        Commands::Config { command } => match command {
            ConfigCommands::SetContext {
                name,
                server,
                insecure,
            } => {
                commands::config::set_context(&name, &server, insecure)?;
            }
            ConfigCommands::UseContext { name } => {
                commands::config::use_context(&name)?;
            }
            ConfigCommands::GetContexts => {
                commands::config::get_contexts()?;
            }
            ConfigCommands::CurrentContext => {
                commands::config::current_context()?;
            }
            ConfigCommands::DeleteContext { name } => {
                commands::config::delete_context(&name)?;
            }
            ConfigCommands::RenameContext { old_name, new_name } => {
                commands::config::rename_context(&old_name, &new_name)?;
            }
            ConfigCommands::SetToken { token } => {
                commands::config::set_token(&token)?;
            }
            ConfigCommands::Show => {
                commands::config::show()?;
            }
            ConfigCommands::Init => {
                commands::config::init()?;
            }
        },
        Commands::Health => {
            let client = client::TsaClient::new(server_url, None, insecure);
            commands::health::check(&client).await?;
        }
    }

    Ok(())
}
