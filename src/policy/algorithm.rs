use color_eyre::{eyre::bail, Report, Result};
use jsonwebtoken::Algorithm;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AcceptedAlgorithm(Algorithm);

impl AcceptedAlgorithm {
    pub fn new(alg: Algorithm) -> Result<AcceptedAlgorithm> {
        if !ACCEPTABLE_ALGORITHMS.contains(&alg) {
            bail!("algorithm is not supported: {:?}", alg);
        }

        Ok(AcceptedAlgorithm(alg))
    }

    pub fn wrapped(&self) -> Algorithm {
        self.0
    }
}

pub const ACCEPTABLE_ALGORITHMS: [Algorithm; 3] =
    [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];

impl TryFrom<String> for AcceptedAlgorithm {
    type Error = Report;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let alg: Result<Algorithm> = match value.to_lowercase().as_str() {
            "rs256" => Ok(Algorithm::RS256),
            "rs384" => Ok(Algorithm::RS384),
            "rs512" => Ok(Algorithm::RS512),
            _ => {
                bail!("unsupported algorithm")
            }
        };
        AcceptedAlgorithm::new(alg?)
    }
}
