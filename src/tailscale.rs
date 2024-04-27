use axum::async_trait;
use color_eyre::Result;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use redact::Secret;

// This module holds functionality related to requesting Tailscale API access tokens from Tailscale's OAuth endpoint.
// Requesters implement the AccessTokenRequester trait.

#[async_trait]
pub trait AccessTokenRequester {
    async fn request_access_token(&self, scopes: Vec<String>) -> Result<Secret<String>>;
}

// OAuth2Requester requests access tokens using the oauth2 crate

pub struct OAuth2Requester {
    oauth: BasicClient,
}

impl OAuth2Requester {
    pub fn new(
        client_id: String,
        client_secret: Secret<String>,
        token_url: String,
    ) -> Result<OAuth2Requester> {
        let oauth = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret.expose_secret().clone())),
            AuthUrl::new("".to_string())?, // this field is ignored in the Client Credentials flow https://docs.rs/oauth2/latest/oauth2/struct.Client.html#method.new
            Some(TokenUrl::new(token_url)?),
        );

        Ok(OAuth2Requester { oauth })
    }
}

#[async_trait]
impl AccessTokenRequester for OAuth2Requester {
    async fn request_access_token(&self, scopes: Vec<String>) -> Result<Secret<String>> {
        let scopes = scopes.iter().map(|s| Scope::new(s.clone()));

        let response = self
            .oauth
            .exchange_client_credentials()
            .add_scopes(scopes)
            .request_async(oauth2::reqwest::async_http_client)
            .await?;

        Ok(Secret::new(response.access_token().secret().clone()))
    }
}
