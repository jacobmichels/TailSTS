use color_eyre::{
    eyre::{bail, Context},
    Result,
};
use log::warn;
use std::{fs, path::PathBuf};

use crate::policy::LocalPolicy;

use super::PolicyLoader;

// Load local policies from the file system
pub struct Fs {
    policy_path: PathBuf,
}

impl Fs {
    pub fn new(policy_path: PathBuf) -> Fs {
        Fs { policy_path }
    }

    fn read_policy_files(&self) -> Result<Vec<LocalPolicy>> {
        if !self.policy_path.is_dir() {
            bail!("policy_path is not a directory")
        }

        let files = self
            .policy_path
            .read_dir()?
            // Filter out invalid DirEntries
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry),
                Err(e) => {
                    warn!("Encountered an invalid DirEntry, skipping it. Error: {}", e);
                    None
                }
            })
            // Filter out DirEntries that aren't files
            .filter(|entry| match entry.file_type() {
                Ok(t) => t.is_file(),
                Err(e) => {
                    warn!(
                        "Unable to test if DirEntry is file, skipping it. Error: {}",
                        e
                    );
                    false
                }
            });

        // Read each file, attempting to deserialize it to a LocalPolicy
        let policies: Vec<LocalPolicy> = files
            .filter_map(|file| {
                let contents = match fs::read_to_string(file.path()) {
                    Ok(contents) => contents,
                    Err(e) => {
                        warn!("failed to read file contents. Error: {}", e);
                        return None;
                    }
                };
                match toml::from_str(&contents) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        warn!("failed to deserialize file contents to toml. Error: {}", e);
                        None
                    }
                }
            })
            .collect();

        Ok(policies)
    }
}

impl PolicyLoader for Fs {
    fn load_policies(&self) -> Result<Vec<LocalPolicy>> {
        let policies = self
            .read_policy_files()
            .wrap_err("failed to read policies")?;

        // TODO: Validate these policies before returning them

        Ok(policies)
    }
}
