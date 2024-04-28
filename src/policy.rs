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
    pub permissions: HashMap<String, String>,
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
            permissions: self.permissions,
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
    pub permissions: HashMap<String, String>,
}
