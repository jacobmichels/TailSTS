use std::path::PathBuf;

use clap::Parser;
use redact::Secret;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, default_value = "policies")]
    pub policies_dir: PathBuf,

    #[arg(long)]
    pub tailscale_client_id: String,

    #[arg(long)]
    pub tailscale_client_secret: Secret<String>,

    #[arg(long, default_value = "https://api.tailscale.com/api/v2/oauth/token")]
    pub tailscale_token_url: String,

    #[arg(long, default_value_t = 8080)]
    pub port: u32,
}
