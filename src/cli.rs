use std::path::PathBuf;

use clap::Parser;
use redact::Secret;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "policies")]
    pub policies_dir: PathBuf,

    #[arg(short, long)]
    pub tailscale_client_id: String,

    #[arg(short, long)]
    pub tailscale_client_secret: Secret<String>,

    #[arg(short, long)]
    pub tailscale_token_url: String,

    #[arg(short, long, default_value_t = 8080)]
    pub port: u32,
}
