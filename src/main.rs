use cache_doctor::{ScanOptions, explain_report, inspect_cache, inspect_cargo_home, report_json};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
enum OutputFormat {
    Json,
    Text,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            other => Err(format!("unknown format {other}; use json or text")),
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "cache-doctor",
    version,
    about = "Inspect local Cargo cache evidence without network access"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect the configured Cargo home.
    Cargo {
        #[arg(long)]
        offline: bool,
        #[arg(long, default_value = "json")]
        format: OutputFormat,
    },
    /// Inspect a specified Cargo cache fixture or cache path.
    Inspect {
        cache_path: PathBuf,
        #[arg(long, default_value = "json")]
        format: OutputFormat,
    },
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("cache-doctor: {error}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: Cli) -> Result<u8, Box<dyn std::error::Error>> {
    let (report, format) = match cli.command {
        Commands::Cargo { offline, format } => {
            (inspect_cargo_home(&ScanOptions { offline }), format)
        }
        Commands::Inspect { cache_path, format } => {
            (inspect_cache(&cache_path, &ScanOptions::default()), format)
        }
    };
    match format {
        OutputFormat::Json => println!("{}", report_json(&report)?),
        OutputFormat::Text => println!("{}", explain_report(&report)),
    }
    Ok(if report.complete { 0 } else { 1 })
}
