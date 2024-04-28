use std::collections::HashMap;

use axum::async_trait;
use color_eyre::Result;
use dyn_clone::DynClone;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, Scope, TokenResponse, TokenUrl};
use redact::Secret;

// This module holds functionality related to requesting Tailscale API access tokens from Tailscale's OAuth endpoint.
// Requesters implement the AccessTokenRequester trait.

#[async_trait]
pub trait AccessTokenRequester: DynClone + Send + Sync {
    async fn request_access_token(&self, scopes: HashMap<String, String>)
        -> Result<Secret<String>>;
}

dyn_clone::clone_trait_object!(AccessTokenRequester);

// OAuth2Requester requests access tokens using the oauth2 crate

#[derive(Clone)]
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
            AuthUrl::new(token_url.clone())?, // this field is ignored in the Client Credentials flow https://docs.rs/oauth2/latest/oauth2/struct.Client.html#method.new
            Some(TokenUrl::new(token_url)?),
        );

        Ok(OAuth2Requester { oauth })
    }
}

#[async_trait]
impl AccessTokenRequester for OAuth2Requester {
    async fn request_access_token(
        &self,
        scopes: HashMap<String, String>,
    ) -> Result<Secret<String>> {
        let scopes: Vec<Scope> = scopes
            .iter()
            .map(|(key, value)| {
                if value == "write" {
                    return key.clone();
                }
                format!("{}:{}", key, value)
            })
            .map(|s| Scope::new(s))
            .collect();

        let response = self
            .oauth
            .exchange_client_credentials()
            .add_scopes(scopes)
            .request_async(oauth2::reqwest::async_http_client)
            .await?;

        Ok(Secret::new(response.access_token().secret().clone()))
    }
}
