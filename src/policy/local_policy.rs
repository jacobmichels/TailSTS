use std::collections::{HashMap, HashSet};

use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use jsonwebtoken::jwk::JwkSet;
use reqwest::Url;
use serde::Deserialize;

use super::{algorithm::AcceptedAlgorithm, policy_with_jwks::PolicyWithJWKS};

// A policy without its JWKS loaded
#[derive(Deserialize, Debug)]
pub struct LocalPolicy {
    pub issuer: HashSet<String>,
    pub subject: String,
    pub algorithm: String,
    pub jwks_url: String,
    pub allowed_scopes: HashMap<String, String>,
}

impl LocalPolicy {
    pub fn attach_jwks(self, jwks: JwkSet) -> Result<PolicyWithJWKS> {
        let alg: AcceptedAlgorithm = self.algorithm.try_into()?;

        Ok(PolicyWithJWKS {
            issuer: self.issuer,
            jwks,
            algorithm: alg,
            allowed_scopes: self.allowed_scopes,
            subject: self.subject,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_iss()?;
        self.validate_alg()?;
        self.validate_sub()?;
        self.validate_jwks_url()?;
        self.validate_allowed_scopes()?;

        Ok(())
    }

    fn validate_iss(&self) -> Result<()> {
        if self.issuer.is_empty() {
            bail!("no issuer set")
        }

        for iss in self.issuer.iter() {
            if iss.is_empty() {
                bail!("issuer has empty entry")
            }
        }

        Ok(())
    }

    fn validate_sub(&self) -> Result<()> {
        if self.subject.is_empty() {
            bail!("subject is empty")
        }

        Ok(())
    }

    fn validate_alg(&self) -> Result<()> {
        let alg: Result<AcceptedAlgorithm> = self.algorithm.clone().try_into();
        if let Err(e) = alg {
            bail!("algorithm is invalid: {}", e);
        }

        Ok(())
    }

    fn validate_jwks_url(&self) -> Result<()> {
        if self.jwks_url.is_empty() {
            bail!("jwks_url is empty");
        }

        Url::parse(&self.jwks_url).wrap_err("jwks_url is not a valid url")?;
        Ok(())
    }

    fn validate_allowed_scopes(&self) -> Result<()> {
        if self.allowed_scopes.is_empty() {
            bail!("no scopes are allowed, nothing can satisfy this policy");
        }

        for (key, value) in self.allowed_scopes.iter() {
            if key.is_empty() {
                bail!("allowed scope with empty key");
            } else if value.is_empty() {
                bail!("allowed scope {} has empty value", key);
            }
        }

        Ok(())
    }
}
