use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use log::{debug, info};

use crate::cli::Cli;

mod cli;
mod policy;
mod server;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    configure_logging();

    run().await
}

async fn run() -> Result<()> {
    // this function is where I can set up dependencies.
    // I could create an "App" or "TailSTS" module with a run function that
    // takes in the dependencies and uses them.

    // What dependencies should I have?
    // - a of policy fetcher
    // - a policy validator
    // - a jwks fetcher
    // - a server(?)
    // and some more

    let args = Cli::parse();
    debug!("CLI args parsed");

    let policies = policy::prepare(&args.policies_dir).await?;
    info!("Read {} policies", policies.len());

    // TODO: gate displaying policies behind a cli flag
    for policy in policies.iter() {
        debug!("{:?}", policy);
    }

    let jwks_list: Vec<JwkSet> = policies.iter().map(|p| p.jwks.clone().unwrap()).collect();
    let jwks_list: Vec<Jwk> = jwks_list.iter().flat_map(|set| set.keys.clone()).collect();
    let jwks = JwkSet { keys: jwks_list };

    server::start(policies, jwks).await?;

    Ok(())
}

fn configure_logging() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init()
}
