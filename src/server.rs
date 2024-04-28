use std::{rc::Rc, sync::Arc};

use crate::{
    fetchers::JWKSFetcher,
    loaders::PolicyLoader,
    policy::{LocalPolicy, PolicyWithJWKS},
    tailscale::AccessTokenRequester,
};
use axum::{routing::post, Router};
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

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

async fn handle_token_request() {}
