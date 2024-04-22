use std::path::PathBuf;

use clap::Parser;
use color_eyre::Result;
use log::debug;
use serde::Deserialize;
use toml::Value;

mod policy;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value = "policies")]
    policies_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    pretty_env_logger::init();
    let args = Cli::parse();
    debug!("cli args parsed");

    let policies = policy::prepare(&args.policies_dir)?;

    // TODO: gate displaying policies behind a cli flag
    println!("Found {} policies", policies.len());
    for policy in policies {
        println!("{:?}", policy);
    }

    // TODO: start http server

    Ok(())
}
