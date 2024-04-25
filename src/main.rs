use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use log::debug;

use crate::{cli::Cli, jwks::reqwestfetcher::ReqwestJWKSFetcher};

mod cli;
mod jwks;
mod loaders;
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
    // - a tailscale client
    // - a server(?)

    // TODO: add another PolicyLoader that wraps a PolicyLoader and validates the policies before returning them
    let provider = loaders::Fs::new(args.policies_dir);

    // My current thought is that I'll pass in the local policy loader to the JWKS fetcher so that it can return an enriched policy of sorts with the fetched JWKS
    // idk though... is JWKS too specific of a module? The goal of it is to get the public key to verify the token. Maybe I call it verifier?
    let _fetcher = ReqwestJWKSFetcher::new(provider);

    Ok(())
}

async fn run() -> Result<()> {
    // This is where I begin to use the dependencies built in main
    Ok(())
}
