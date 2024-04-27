use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use fetchers::JWKSFetcher;
use loaders::PolicyLoader;
use log::debug;
use tailscale::AccessTokenRequester;

use crate::cli::Cli;

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

    // this function is where I can set up dependencies.
    // I could create an "App" or "TailSTS" module with a run function that
    // takes in the dependencies and uses them.

    // What dependencies should I have?
    // - a policy provider
    // - a jwks fetcher
    // - a tailscale client
    // - a server(?)

    // TODO: add another PolicyLoader that wraps a PolicyLoader and validates the policies before returning them
    let fs_loader = loaders::Fs::new(args.policies_dir);

    // My current thought is that I'll pass in the local policy loader to the JWKS fetcher so that it can return an enriched policy of sorts with the fetched JWKS
    // idk though... is JWKS too specific of a module? The goal of it is to get the public key to verify the token. Maybe I call it verifier?
    let reqwest_fetcher = fetchers::Reqwest::new();

    let tailscale = tailscale::OAuth2Requester::new(
        args.tailscale_client_id,
        args.tailscale_client_secret,
        args.tailscale_token_url,
    )?;

    run(
        Box::new(fs_loader),
        Box::new(reqwest_fetcher),
        Box::new(tailscale),
    )
    .await?;

    Ok(())
}

async fn run(
    loader: Box<dyn PolicyLoader>,
    fetcher: Box<dyn JWKSFetcher>,
    _tailscale_oauth: Box<dyn AccessTokenRequester>,
) -> Result<()> {
    // This is where I begin to use the dependencies built in main

    let local_policies = loader.load_policies()?;

    let _enriched_policies = fetcher.enrich_policies(local_policies).await?;

    Ok(())
}
