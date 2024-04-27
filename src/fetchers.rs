use axum::async_trait;
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

// This module holds functionality related to fetching JWK sets from a url.
// Fetchers implement the JWKSFetcher trait.

#[async_trait]
pub trait JWKSFetcher {
    async fn fetch_jwks(&self, jwks_url: &str) -> Result<JwkSet>;
}

// Reqwest fetches JWK sets using the reqwest library

pub struct ReqwestJWKSFetcher {
    client: reqwest::Client,
}

impl ReqwestJWKSFetcher {
    pub fn new() -> ReqwestJWKSFetcher {
        let client = reqwest::Client::new();
        ReqwestJWKSFetcher { client }
    }
}

#[async_trait]
impl JWKSFetcher for ReqwestJWKSFetcher {
    async fn fetch_jwks(&self, jwks_url: &str) -> Result<JwkSet> {
        Ok(self.client.get(jwks_url).send().await?.json().await?)
    }
}
