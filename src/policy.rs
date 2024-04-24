use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;
use std::{
    fs::{self},
    path::Path,
};
use toml::Value;

#[derive(Clone, Debug, Deserialize)]
pub struct Policy {
    pub issuer: String,
    pub subject: String,
    pub permissions: Value,
    pub jwks_url: String,
    #[serde(skip)]
    pub jwks: Option<JwkSet>,
}

impl Policy {
    fn validate(&self) -> Result<()> {
        // TODO: implement
        Ok(())
    }
}

pub async fn prepare(policies_dir: &Path) -> Result<Vec<Policy>> {
    let mut policies = read_policy_files(policies_dir).wrap_err("failed to read policies")?;
    // TODO: make thos function fail if validation fails
    policies.iter().for_each(|p| p.validate().unwrap());

    for policy in policies.iter_mut() {
        let jwks: JwkSet = reqwest::get(policy.jwks_url.clone())
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        policy.jwks = Some(jwks);
    }

    Ok(policies)
}

fn read_policy_files(policies_dir: &Path) -> Result<Vec<Policy>> {
    if !policies_dir.is_dir() {
        bail!("policies_dir is not a directory")
    }

    // TODO: remove the prints and collects
    let valid_entries = policies_dir.read_dir()?.filter_map(|entry| match entry {
        Ok(entry) => Some(entry),
        Err(_) => {
            //TODO: log error
            None
        }
    });
    let file_entries = valid_entries.filter(|entry| match entry.file_type() {
        Ok(t) => t.is_file(),
        Err(_) => {
            //TODO: log error
            false
        }
    });

    let mut policies = Vec::new();
    for file in file_entries {
        let file_str = fs::read_to_string(file.path()).unwrap();
        let policy: Policy = toml::from_str(&file_str).unwrap();
        policies.push(policy);
    }

    Ok(policies)
}
