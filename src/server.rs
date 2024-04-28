use std::{collections::HashMap, sync::Arc};

use crate::{
    fetchers::JWKSFetcher,
    loaders::PolicyLoader,
    policy::{LocalPolicy, PolicyWithJWKS},
    tailscale::AccessTokenRequester,
};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use axum_auth::AuthBearer;
use color_eyre::Result;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{Jwk, JwkSet},
    Algorithm, DecodingKey, Validation,
};
use log::{debug, error};
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    policies: Vec<PolicyWithJWKS>,
    requester: Box<dyn AccessTokenRequester>,
}

pub async fn start(
    loader: Box<dyn PolicyLoader>,
    fetcher: Box<dyn JWKSFetcher>,
    requester: Box<dyn AccessTokenRequester>,
    port: u32,
) -> Result<()> {
    // This is where I begin to use the dependencies built in main

    let local_policies = loader.load_policies()?;

    let enriched_policies = enrich_policies(local_policies, fetcher).await?;

    let state = Arc::new(AppState {
        policies: enriched_policies,
        requester,
    });

    let router = Router::new().route("/", post(handle_token_request).with_state(state));
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

async fn enrich_policies(
    policies: Vec<LocalPolicy>,
    fetcher: Box<dyn JWKSFetcher>,
) -> Result<Vec<PolicyWithJWKS>> {
    let mut enriched_policies = Vec::with_capacity(policies.len());
    for policy in policies.into_iter() {
        let jwks: JwkSet = fetcher.fetch_jwks(&policy.jwks_url).await?;
        enriched_policies.push(policy.attach_jwks(jwks));
    }

    Ok(enriched_policies)
}

#[derive(Deserialize)]
struct TokenRequest {
    scopes: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,        // Optional. Issuer
    nbf: Option<usize>, // Optional. Not Before (as UTC timestamp)
    sub: String,        // Optional. Subject (whom token refers to)
}

const ACCEPTABLE_ALGORITHMS: [Algorithm; 3] =
    [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];

async fn handle_token_request(
    State(state): State<Arc<AppState>>,
    AuthBearer(token): AuthBearer,
    Json(payload): Json<TokenRequest>,
) -> StatusCode {
    // this is the handler that clients will hit asking for tailscale access tokens
    // how to proceed:
    // 1. fetch and validate the token with jwks
    // 2. check if the issuer and subject match any of the policies. if not, reject
    // 3. check the allowed scopes of the matched policy. if the requester is requesting more, reject
    // 4. request access token from tailscale and return it to the client

    let header = decode_header(&token).unwrap();
    if !ACCEPTABLE_ALGORITHMS.contains(&header.alg) {
        return StatusCode::BAD_REQUEST;
    }

    let kid = match header.kid {
        Some(kid) => kid,
        None => return StatusCode::BAD_REQUEST,
    };

    let (policy, jwk) = match match_policy(state.policies.clone(), kid) {
        Some(policy) => policy,
        None => return StatusCode::UNAUTHORIZED,
    };

    let mut validation = Validation::new(policy.algorithm);
    validation.validate_aud = false; // TOOD do I need to turn this off? the docs say this is a bad idea
    validation.sub = Some(policy.subject.clone());
    validation.iss = Some(policy.issuer.clone());

    let decoding_key = match DecodingKey::from_jwk(&jwk) {
        Ok(key) => key,
        Err(e) => {
            error!("failed to create DecodingKey: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let claims = match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(claims) => claims,
        Err(e) => {
            error!("token failed to decode: {}", e);
            return StatusCode::UNAUTHORIZED;
        }
    };

    debug!("token validated");

    let requested_scopes = payload.scopes;
    for (scope_name, scope_value) in requested_scopes {
        if !policy.check_scope_allowed(&scope_name, &scope_value) {
            debug!("scope {}:{} not allowed", scope_name, scope_value);
            return StatusCode::UNAUTHORIZED;
        }
    }

    debug!("requested scopes allowed");

    StatusCode::OK
}

fn match_policy(policies: Vec<PolicyWithJWKS>, kid: String) -> Option<(PolicyWithJWKS, Jwk)> {
    for policy in policies {
        let jwk = policy.jwks.find(&kid);
        if let Some(jwk) = jwk {
            return Some((policy.clone(), jwk.clone()));
        }
    }

    None
}
