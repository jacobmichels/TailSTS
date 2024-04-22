use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use serde::Deserialize;
use std::{
    fs::{self, DirEntry},
    path::Path,
};
use toml::Value;

#[derive(Clone, Debug, Deserialize)]
pub struct Policy {
    issuer: String,
    subject: String,
    permissions: Value,
}

impl Policy {
    fn validate(&self) -> Result<()> {
        // TODO: implement
        Ok(())
    }
}

pub fn prepare(policies_dir: &Path) -> Result<Vec<Policy>> {
    let policies = read_policy_files(policies_dir).wrap_err("failed to read policies")?;
    // TODO: make thos function fail if validation fails
    policies.iter().for_each(|p| p.validate().unwrap());

    Ok(policies)
}

fn read_policy_files(policies_dir: &Path) -> Result<Vec<Policy>> {
    if !policies_dir.is_dir() {
        bail!("policies_dir is not a directory")
    }

    // TODO: remove the prints and collects
    let valid_entries: Vec<DirEntry> = policies_dir
        .read_dir()?
        .filter_map(|entry| match entry {
            Ok(entry) => Some(entry),
            Err(_) => {
                //TODO: log error
                None
            }
        })
        .collect();
    println!("Found {} valid entries", valid_entries.len());

    let file_entries: Vec<DirEntry> = valid_entries
        .into_iter()
        .filter(|entry| match entry.file_type() {
            Ok(t) => t.is_file(),
            Err(_) => {
                //TODO: log error
                false
            }
        })
        .collect();
    println!("Found {} file entries", file_entries.len());

    let mut policies = Vec::new();
    for file in file_entries {
        let file_str = fs::read_to_string(file.path()).unwrap();
        let policy: Policy = toml::from_str(&file_str).unwrap();
        policies.push(policy);
    }

    Ok(policies)
}
