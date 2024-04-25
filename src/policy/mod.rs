use std::collections::HashMap;

use color_eyre::Result;
use serde::Deserialize;

pub mod fspolicyprovider;

#[derive(Deserialize, Debug)]
pub struct Policy {
    pub issuer: String,
    pub subject: String,
    pub jwks_url: String,
    pub permissions: HashMap<String, String>,
}

pub trait PolicyProvider {
    fn get_policies(&self) -> Result<Vec<Policy>>;
}
