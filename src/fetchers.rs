use axum::async_trait;
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

use crate::policy::{LocalPolicy, PolicyWithJWKS};

// This module holds functionality related to fetching JWK sets from a url.
// Fetchers implement the JWKSFetcher trait.

#[async_trait]
pub trait JWKSFetcher {
    async fn enrich_policies(&self, policies: Vec<LocalPolicy>) -> Result<Vec<PolicyWithJWKS>>;
}

// Reqwest fetches JWK sets using the reqwest library

pub struct Reqwest {
    client: reqwest::Client,
}

impl Reqwest {
    pub fn new() -> Reqwest {
        let client = reqwest::Client::new();
        Reqwest { client }
    }
}

#[async_trait]
impl JWKSFetcher for Reqwest {
    async fn enrich_policies(&self, policies: Vec<LocalPolicy>) -> Result<Vec<PolicyWithJWKS>> {
        // Non-trivial to convert this to map/reduce since async closures are not stable
        let mut enriched_policies = Vec::with_capacity(policies.len());
        for policy in policies.into_iter() {
            let jwks: JwkSet = self
                .client
                .get(&policy.jwks_url)
                .send()
                .await?
                .json()
                .await?;
            enriched_policies.push(policy.attach_jwks(jwks));
        }

        Ok(enriched_policies)
    }
}
