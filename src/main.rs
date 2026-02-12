//! softKMS daemon - Main entry point

use softkms::{Config, Result};
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("Starting softKMS daemon v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = load_config().await?;
    info!("Configuration loaded");
    
    // Start daemon
    softkms::daemon::start(config).await?;
    
    Ok(())
}

async fn load_config() -> Result<Config> {
    // TODO: Load from config file
    Ok(Config::default())
}