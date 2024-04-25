use axum::async_trait;
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

// This module holds functionality related to fetching JWK sets from a url.
// Fetchers implement the JWKSFetcher trait.

#[async_trait]
pub trait JWKSFetcher {
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet>;
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
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet> {
        Ok(self.client.get(url).send().await?.json().await?)
    }
}
