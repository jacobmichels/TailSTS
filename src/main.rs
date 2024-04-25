use std::collections::HashMap;

use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use jwks::JWKSFetcher;
use log::debug;
use policy::PolicyProvider;

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
    let provider = FsPolicyProvider::new(args.policies_dir);

    // My current thought is that I'll pass in the local policy provider to the JWKS fetcher so that it can return an enriched policy of sorts with the fetched JWKS
    // Naming things is hard though. Where would such an enriched policy type live? My brain says in the policy module, but it doesn't get returned by the policy module, but the jwks module.
    // Maybe I need to reconsider these modules.
    let _fetcher = ReqwestJWKSFetcher::new(provider);

    Ok(())
}

async fn run() -> Result<()> {
    Ok(())
}
