use std::collections::{HashMap, HashSet};

use jsonwebtoken::{jwk::JwkSet, Algorithm};
use serde::Deserialize;

// This file contains Policy struct definitions used throughout the program.

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
    pub fn attach_jwks(self, jwks: JwkSet) -> PolicyWithJWKS {
        let alg = match self.algorithm.to_lowercase().as_str() {
            "rs256" => Algorithm::RS256,
            "rs384" => Algorithm::RS384,
            "rs512" => Algorithm::RS512,
            _ => {
                panic!("invalid policy") // TODO: I can do better...
            }
        };

        PolicyWithJWKS {
            issuer: self.issuer,
            jwks,
            algorithm: alg,
            allowed_scopes: self.allowed_scopes,
            subject: self.subject,
        }
    }
}

// A policy without its JWKS loaded
#[derive(Deserialize, Debug, Clone)]
pub struct PolicyWithJWKS {
    pub issuer: HashSet<String>,
    pub subject: String,
    pub algorithm: Algorithm,
    pub jwks: JwkSet,
    pub allowed_scopes: HashMap<String, String>, // TODO: I don't like using strings to represent scopes, but don't want to update this app when new scopes are made available. Any way to look at the Tailscale API to get available scopes??
}

impl PolicyWithJWKS {
    pub fn check_scope_allowed(&self, scope_name: &str, scope_value: &str) -> bool {
        match self.allowed_scopes.get(scope_name) {
            Some(allowed_value) => {
                if allowed_value == "read" && scope_value == "read" {
                    true
                } else if allowed_value == "write" && scope_value == "write" {
                    true
                } else if allowed_value == "write" && scope_value == "read" {
                    true
                } else {
                    false
                }
            }
            None => false,
        }
    }
}
