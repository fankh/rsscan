use anyhow::Result;
use clap::Parser;
use rsscan::agent::{AgentConfig, VulnAgent};
use std::time::Duration;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
#[command(name = "rsscan-agent")]
#[command(about = "RsScan Endpoint Agent")]
struct Args {
    /// Server URL
    #[arg(short, long)]
    server: String,

    /// API key
    #[arg(short, long)]
    api_key: String,

    /// Scan interval in seconds
    #[arg(short, long, default_value = "3600")]
    interval: u64,

    /// Run once (don't daemon)
    #[arg(long)]
    once: bool,

    /// Debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let level = if args.debug { Level::DEBUG } else { Level::INFO };
    FmtSubscriber::builder().with_max_level(level).init();

    let config = AgentConfig::new(args.server, args.api_key)
        .with_interval(Duration::from_secs(args.interval));

    let mut agent = VulnAgent::new(config);

    if args.once {
        agent.collect_and_report().await?;
    } else {
        agent.run_daemon().await?;
    }

    Ok(())
}
