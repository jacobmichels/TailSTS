use color_eyre::Result;

// Loads policies from a wrapped PolicyLoader,
// ensuring they're valid before passing them up to the caller.

use crate::policy::LocalPolicy;

use super::PolicyLoader;

pub struct ValidatingPolicyLoader {
    wrapped: Box<dyn PolicyLoader>,
}

impl ValidatingPolicyLoader {
    pub fn new(wrapped: Box<dyn PolicyLoader>) -> ValidatingPolicyLoader {
        ValidatingPolicyLoader { wrapped }
    }
}

impl PolicyLoader for ValidatingPolicyLoader {
    fn load_policies(&self) -> Result<Vec<LocalPolicy>> {
        let raw_policies = self.wrapped.load_policies()?;

        for policy in raw_policies.iter() {
            policy.validate()?;
        }

        Ok(raw_policies)
    }
}
