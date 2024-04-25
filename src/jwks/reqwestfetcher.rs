use axum::async_trait;
use color_eyre::eyre::Result;
use jsonwebtoken::jwk::JwkSet;

use super::JWKSFetcher;

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
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet> {
        Ok(self.client.get(url).send().await?.json().await?)
    }
}
