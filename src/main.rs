use axum::routing::{get, post};
use clap::Parser;
use color_eyre::eyre::{eyre, Result};
use rbx_studio_server::*;
use rmcp::ServiceExt;
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::{self, EnvFilter};
mod asset_types;
mod audit;
mod auth;
mod cli;
mod error;
mod install;
mod oauth;
mod open_cloud;
mod policy;
mod rbx_studio_server;
mod secret_store;
mod token_store;

use token_store::TokenCache;

/// Simple MCP proxy for Roblox Studio
/// Run without arguments to install the plugin
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Run as MCP server on stdio
    #[arg(short, long)]
    stdio: bool,

    /// Tool set to serve: `studio` (Studio plugin tools plus Open Cloud tools)
    /// or `cloud` (Open Cloud tools only; no Studio plugin port is bound)
    #[arg(long, value_enum, default_value_t = ServerMode::Studio)]
    mode: ServerMode,

    #[command(subcommand)]
    command: Option<Command>,
}

/// One-time terminal commands for credentials. They never run as MCP tools, so
/// an agent cannot read or change a secret.
#[derive(clap::Subcommand)]
enum Command {
    /// Store an API key (default) or OAuth client secret through a hidden prompt
    SetKey {
        #[arg(long, value_enum, default_value_t = cli::KeyKind::ApiKey)]
        kind: cli::KeyKind,
    },
    /// Remove a stored API key (default) or OAuth client secret
    DeleteKey {
        #[arg(long, value_enum, default_value_t = cli::KeyKind::ApiKey)]
        kind: cli::KeyKind,
    },
    /// Show what is configured and what Roblox reports about the API key (no secrets printed)
    AuthStatus,
    /// Import the old plaintext OAuth token file into secure storage, then ask before deleting it
    MigrateTokens,
}

async fn run_command(command: Command) -> Result<()> {
    let store = secret_store::default_store();
    match command {
        Command::SetKey { kind } => cli::set_key(store.as_ref(), kind),
        Command::DeleteKey { kind } => cli::delete_key(store.as_ref(), kind),
        Command::AuthStatus => cli::auth_status(store).await,
        Command::MigrateTokens => cli::migrate_tokens(
            store.as_ref(),
            &mut io::stdin().lock(),
            &mut io::stdout().lock(),
        ),
    }
}

impl Args {
    /// Reject combinations that must never fall through to the installer:
    /// without `--stdio` the binary installs the Studio plugin, which makes no
    /// sense (and is surprising) in cloud mode.
    fn check(&self) -> Result<()> {
        if self.mode == ServerMode::Cloud && !self.stdio {
            return Err(eyre!(
                "--mode cloud requires --stdio (running without --stdio installs the Studio plugin)"
            ));
        }
        Ok(())
    }
}

/// Bind the Studio plugin port and serve the plugin endpoints, or fall back to
/// proxying through the instance that already holds the port. Only called in
/// studio mode, so cloud mode never touches the port.
async fn spawn_plugin_server(
    server_state: PackedState,
    close_rx: tokio::sync::oneshot::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    let listener =
        tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), STUDIO_PLUGIN_PORT)).await;
    if let Ok(listener) = listener {
        let app = axum::Router::new()
            .route("/request", get(request_handler))
            .route("/response", post(response_handler))
            .route("/proxy", post(proxy_handler))
            .with_state(server_state);
        tracing::info!("This MCP instance is HTTP server listening on {STUDIO_PLUGIN_PORT}");
        tokio::spawn(async {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    _ = close_rx.await;
                })
                .await
                .unwrap();
        })
    } else {
        tracing::info!("This MCP instance will use proxy since port is busy");
        tokio::spawn(async move {
            dud_proxy_loop(server_state, close_rx).await;
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        // Every log line passes through the redactor so a key or token can
        // never reach stderr, even from a third-party crate's debug output.
        .with_writer(|| secret_store::RedactingWriter(io::stderr()))
        .with_target(false)
        .with_thread_ids(true)
        .init();

    let args = Args::parse();
    args.check()?;
    if let Some(command) = args.command {
        return run_command(command).await;
    }
    if !args.stdio {
        return install::install().await;
    }

    tracing::debug!("Debug MCP tracing enabled");

    let server_state = Arc::new(Mutex::new(AppState::new()));

    let (close_tx, close_rx) = tokio::sync::oneshot::channel();

    let server_handle = match args.mode {
        ServerMode::Studio => Some(spawn_plugin_server(Arc::clone(&server_state), close_rx).await),
        ServerMode::Cloud => {
            tracing::info!("Cloud mode: Studio plugin port and server are not started");
            None
        }
    };

    // Credentials live in the secret store (Windows DPAPI) and are resolved on
    // every call, so `set-key` takes effect without a restart. Without any
    // credentials the Open Cloud tools return a setup hint instead.
    let store = secret_store::default_store();
    tracing::info!("Secret storage backend: {}", store.backend());
    let token_cache = Arc::new(TokenCache::new(Arc::clone(&store)));
    let auth = Arc::new(auth::AuthManager::new(store, token_cache));

    let service = RBXStudioServer::new(Arc::clone(&server_state), auth, args.mode)
        .serve(rmcp::transport::stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;
    service.waiting().await?;

    close_tx.send(()).ok();
    if let Some(server_handle) = server_handle {
        tracing::info!("Waiting for web server to gracefully shutdown");
        server_handle.await.ok();
    }
    tracing::info!("Bye!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("rbx-studio-mcp").chain(args.iter().copied()))
    }

    #[test]
    fn mode_defaults_to_studio() {
        assert_eq!(parse(&["--stdio"]).unwrap().mode, ServerMode::Studio);
        assert_eq!(parse(&[]).unwrap().mode, ServerMode::Studio);
    }

    #[test]
    fn mode_parses_studio_and_cloud() {
        assert_eq!(
            parse(&["--stdio", "--mode", "studio"]).unwrap().mode,
            ServerMode::Studio
        );
        assert_eq!(
            parse(&["--stdio", "--mode", "cloud"]).unwrap().mode,
            ServerMode::Cloud
        );
        assert_eq!(
            parse(&["--stdio", "--mode=cloud"]).unwrap().mode,
            ServerMode::Cloud
        );
    }

    #[test]
    fn mode_rejects_unknown_values() {
        assert!(parse(&["--stdio", "--mode", "both"]).is_err());
        assert!(parse(&["--stdio", "--mode"]).is_err());
    }

    #[test]
    fn credential_subcommands_parse_and_default_to_the_api_key() {
        let set = parse(&["set-key"]).unwrap();
        assert!(matches!(
            set.command,
            Some(Command::SetKey {
                kind: cli::KeyKind::ApiKey
            })
        ));
        let oauth = parse(&["set-key", "--kind", "oauth-client-secret"]).unwrap();
        assert!(matches!(
            oauth.command,
            Some(Command::SetKey {
                kind: cli::KeyKind::OauthClientSecret
            })
        ));
        assert!(matches!(
            parse(&["auth-status"]).unwrap().command,
            Some(Command::AuthStatus)
        ));
        assert!(matches!(
            parse(&["migrate-tokens"]).unwrap().command,
            Some(Command::MigrateTokens)
        ));
        assert!(parse(&["--stdio"]).unwrap().command.is_none());
    }

    #[test]
    fn a_secret_can_not_be_passed_as_an_argument() {
        assert!(parse(&["set-key", "--value", "abc"]).is_err());
        assert!(parse(&["set-key", "abc"]).is_err());
    }

    #[test]
    fn cloud_mode_without_stdio_is_refused_before_the_installer() {
        assert!(parse(&["--mode", "cloud"]).unwrap().check().is_err());
        assert!(parse(&["--stdio", "--mode", "cloud"])
            .unwrap()
            .check()
            .is_ok());
        // Unchanged: bare invocation still means "install the plugin".
        assert!(parse(&[]).unwrap().check().is_ok());
    }
}
