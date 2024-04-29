use color_eyre::Result;

use crate::policy::LocalPolicy;

mod fs;
mod validating;

pub use fs::FsPolicyLoader;
pub use validating::ValidatingPolicyLoader;

// This module holds functionality related to loading policies.
// This could be fetching them from the file system, environment, remote bucket, etc.
// Loaders implement the PolicyLoader trait.

pub trait PolicyLoader {
    fn load_policies(&self) -> Result<Vec<LocalPolicy>>;
}
