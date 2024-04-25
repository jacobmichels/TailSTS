use std::collections::HashMap;

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;

// This file contains Policy struct definitions used throughout the program.

// A policy without its JWKS loaded
#[derive(Deserialize, Debug)]
pub struct LocalPolicy {
    pub issuer: String,
    pub subject: String,
    pub jwks_url: String,
    pub permissions: HashMap<String, String>,
}

// A policy without its JWKS loaded
#[derive(Deserialize, Debug)]
pub struct PolicyWithJWKS {
    pub issuer: String,
    pub subject: String,
    pub jwks: JwkSet,
    pub permissions: HashMap<String, String>,
}
