use std::{path::PathBuf, sync::Arc};

use axum::{extract::State, routing::post, Router};
use axum_auth::AuthBearer;
use clap::Parser;
use color_eyre::Result;
use env_logger::Env;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use log::{debug, info};
use policy::Policy;
use serde::Deserialize;

mod policy;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "policies")]
    policies_dir: PathBuf,
}

struct AppState {
    policies: Vec<Policy>,
    jwks: JwkSet,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    configure_logging();
    let args = Cli::parse();
    debug!("CLI args parsed");

    run(args).await
}

async fn run(args: Cli) -> Result<()> {
    let policies = policy::prepare(&args.policies_dir).await?;
    info!("Read {} policies", policies.len());

    // TODO: gate displaying policies behind a cli flag
    for policy in policies.iter() {
        debug!("{:?}", policy);
    }

    // let jwks = policies
    //     .iter()
    //     .map(|p| p.jwks.as_ref().unwrap())
    //     .reduce(|acc, jwks| {
    //         jwks.keys.iter().for_each(|key| acc.keys.push(key.clone()));
    //         acc
    //     })
    //     .unwrap()
    //     .clone();

    let jwks_list: Vec<JwkSet> = policies.iter().map(|p| p.jwks.clone().unwrap()).collect();
    let jwks_list: Vec<Jwk> = jwks_list.iter().flat_map(|set| set.keys.clone()).collect();
    let jwks = JwkSet { keys: jwks_list };

    let state = Arc::new(AppState { policies, jwks });

    let app = Router::new()
        .route("/token", post(token_post))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server starting");
    axum::serve(listener, app).await?;

    Ok(())
}

#[derive(Deserialize)]
struct TokenRequest {
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct Claims {
    aud: String,        // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: Option<usize>, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    nbf: Option<usize>, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

async fn token_post(State(state): State<Arc<AppState>>, AuthBearer(token): AuthBearer) {
    // this is the handler that clients will hit asking for tailscale access tokens
    // how to proceed:
    // 1. fetch and validate the token with jwks
    // 2. check if the issuer and subject match any of the policies. if not, reject
    // 3. check the allowed scopes of the matched policy. if the requester is requesting more, reject
    // 4. request access token from tailscale and return it to the client

    let header = decode_header(&token).unwrap();
    let jwk = state.jwks.find(&header.kid.unwrap()).unwrap();

    let mut v = Validation::new(Algorithm::RS256);
    v.validate_aud = false; // TOOD do I need to turn this off? the docs say this is a bad idea

    let claims = decode::<Claims>(&token, &DecodingKey::from_jwk(jwk).unwrap(), &v).unwrap();
    debug!("token validated")
}

fn configure_logging() {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init()
}
