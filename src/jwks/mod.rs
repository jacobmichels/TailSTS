use axum::async_trait;
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

pub mod reqwestfetcher;

#[async_trait]
pub trait JWKSFetcher {
    async fn fetch_jwks(&self, url: &str) -> Result<JwkSet>;
}
