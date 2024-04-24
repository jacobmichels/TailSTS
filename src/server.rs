use std::sync::Arc;

use axum::{extract::State, routing::post, Router};
use axum_auth::AuthBearer;
use color_eyre::Result;
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use log::{debug, info};
use serde::Deserialize;

use crate::policy::Policy;

struct AppState {
    policies: Vec<Policy>,
    jwks: JwkSet,
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

pub async fn start(policies: Vec<Policy>, jwks: JwkSet) -> Result<()> {
    let state = Arc::new(AppState { policies, jwks });

    let app = Router::new()
        .route("/token", post(token_post))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server starting");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn token_post(State(state): State<Arc<AppState>>, AuthBearer(token): AuthBearer) {
    // this is the handler that clients will hit asking for tailscale access tokens
    // how to proceed:
    // 1. fetch and validate the token with jwks
    // 2. check if the issuer and subject match any of the policies. if not, reject
    // 3. check the allowed scopes of the matched policy. if the requester is requesting more, reject
    // 4. request access token from tailscale and return it to the client

    let header = jsonwebtoken::decode_header(&token).unwrap();
    let jwk = state.jwks.find(&header.kid.unwrap()).unwrap();

    let mut v = Validation::new(Algorithm::RS256);
    v.validate_aud = false; // TOOD do I need to turn this off? the docs say this is a bad idea

    let claims =
        jsonwebtoken::decode::<Claims>(&token, &DecodingKey::from_jwk(jwk).unwrap(), &v).unwrap();
    debug!("token validated")
}
