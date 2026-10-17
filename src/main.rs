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
mod error;
mod install;
mod oauth;
mod open_cloud;
mod policy;
mod rbx_studio_server;
mod secret_store;
mod token_store;

use oauth::OAuthConfig;
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
        .with_writer(io::stderr)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    let args = Args::parse();
    args.check()?;
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

    // OAuth config is optional — env vars are only needed for the upload /
    // asset-management tools. Missing env vars simply means those tools
    // return a "set these env vars and restart" error.
    let oauth_config = OAuthConfig::from_env();
    if oauth_config.is_some() {
        tracing::info!(
            "OAuth env vars detected. Open Cloud tools (upload_asset, etc.) are available."
        );
    } else {
        tracing::info!(
            "ROBLOX_OAUTH_CLIENT_ID / ROBLOX_OAUTH_CLIENT_SECRET not set; Open Cloud tools disabled."
        );
    }
    let token_cache = Arc::new(TokenCache::new());

    // Create an instance of our counter router
    let service = RBXStudioServer::new(
        Arc::clone(&server_state),
        token_cache,
        oauth_config,
        args.mode,
    )
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
