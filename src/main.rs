use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use log::debug;

use crate::{
    cli::Cli, jwks::reqwestfetcher::ReqwestJWKSFetcher, policy::fspolicyprovider::FsPolicyProvider,
};

mod cli;
mod jwks;
mod policy;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let args = Cli::parse();
    debug!("CLI args parsed");

    // this function is where I can set up dependencies.
    // I could create an "App" or "TailSTS" module with a run function that
    // takes in the dependencies and uses them.

    // What dependencies should I have?
    // - a policy provider
    // - a jwks fetcher
    // - a server(?)

    // TODO: add another PolicyProvider that wraps a PolicyProvider and validates the policies before returning them
    let _provider = FsPolicyProvider::new(args.policies_dir);

    // TODO: add a wrapping caching fetcher
    let _fetcher = ReqwestJWKSFetcher::new();

    Ok(())
}
