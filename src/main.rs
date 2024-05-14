use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use log::debug;

use crate::cli::Cli;

mod cli;
mod fetchers;
mod loader;
mod policy;
mod server;
mod tailscale;

#[tokio::main]
async fn main() -> Result<()> {
    init().expect("Failed to initialize required components");

    let args = Cli::parse();
    debug!("CLI args parsed");

    run(args).await?;

    Ok(())
}

fn init() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    Ok(())
}

async fn run(c: Cli) -> Result<()> {
    // this function is where I set up dependencies.

    let fs_loader = loader::FsPolicyLoader::new(c.policies_dir);
    let validating_loader = loader::ValidatingPolicyLoader::new(Box::new(fs_loader));

    let reqwest_fetcher = fetchers::ReqwestJWKSFetcher::new();

    let tailscale = tailscale::OAuth2Requester::new(
        c.tailscale_client_id,
        c.tailscale_client_secret,
        c.tailscale_token_url,
    )?;

    debug!("dependencies initialized, starting app");
    server::start(
        Box::new(validating_loader),
        Box::new(reqwest_fetcher),
        Box::new(tailscale),
        c.port,
    )
    .await?;

    Ok(())
}