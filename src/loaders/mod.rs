use crate::policy::LocalPolicy;
use color_eyre::Result;

mod fs;

pub use fs::Fs;

// This module holds functionality related to loading policies.
// This could be fetching them from the file system, environment, remote bucket, etc.
// Loaders implement the PolicyLoader trait.

pub trait PolicyLoader {
    fn load_policies(&self) -> Result<Vec<LocalPolicy>>;
}
