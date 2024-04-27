use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use log::debug;

use crate::cli::Cli;

mod app;
mod cli;
mod fetchers;
mod loaders;
mod policy;
mod tailscale;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let args = Cli::parse();
    debug!("CLI args parsed");

    run(args).await?;

    Ok(())
}

async fn run(c: Cli) -> Result<()> {
    // this function is where I can set up dependencies.

    // TODO: add another PolicyLoader that wraps a PolicyLoader and validates the policies before returning them
    let fs_loader = loaders::FsPolicyLoader::new(c.policies_dir);

    let reqwest_fetcher = fetchers::ReqwestJWKSFetcher::new();

    let tailscale = tailscale::OAuth2Requester::new(
        c.tailscale_client_id,
        c.tailscale_client_secret,
        c.tailscale_token_url,
    )?;

    debug!("dependencies initialized, starting app");
    app::start(
        Box::new(fs_loader),
        Box::new(reqwest_fetcher),
        Box::new(tailscale),
    )
    .await?;

    Ok(())
}
