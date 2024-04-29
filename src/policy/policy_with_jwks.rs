use std::collections::{HashMap, HashSet};

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;

use super::algorithm::AcceptedAlgorithm;

// A policy without its JWKS loaded
#[derive(Deserialize, Debug, Clone)]
pub struct PolicyWithJWKS {
    pub issuer: HashSet<String>,
    pub subject: String,
    pub algorithm: AcceptedAlgorithm,
    pub jwks: JwkSet,
    pub allowed_scopes: HashMap<String, String>, // TODO: I don't like using strings to represent scopes, but don't want to update this app when new scopes are made available. Any way to look at the Tailscale API to get available scopes??
}

impl PolicyWithJWKS {
    pub fn check_scope_allowed(&self, scope_name: &str, scope_value: &str) -> bool {
        match self.allowed_scopes.get(scope_name) {
            Some(allowed_value) => {
                (allowed_value == "read" && scope_value == "read")
                    || (allowed_value == "write" && scope_value == "write")
                    || (allowed_value == "write" && scope_value == "read")
            }
            None => false,
        }
    }
}
