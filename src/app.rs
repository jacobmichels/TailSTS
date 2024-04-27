use crate::{
    fetchers::JWKSFetcher,
    loaders::PolicyLoader,
    policy::{LocalPolicy, PolicyWithJWKS},
    tailscale::AccessTokenRequester,
};
use color_eyre::Result;
use jsonwebtoken::jwk::JwkSet;

pub async fn start(
    loader: Box<dyn PolicyLoader>,
    fetcher: Box<dyn JWKSFetcher>,
    requester: Box<dyn AccessTokenRequester>,
) -> Result<()> {
    // This is where I begin to use the dependencies built in main

    let local_policies = loader.load_policies()?;

    let _enriched_policies = enrich_policies(local_policies, fetcher).await?;

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
