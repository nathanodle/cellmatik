//! CLI surface: default subcommand = run the service; `token` subcommands
//! manage client tokens (spec §2).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cellmatik", version, about = "Cellular gateway: SMS, voice, and MMS over LAN HTTP")]
pub struct Cli {
    /// Path to config.toml
    #[arg(long, default_value = "/etc/cellmatik/config.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub cmd: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Token admin (spec §2 — CLI only, never an API)
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    /// Create a client + token; prints the token exactly once
    Add { name: String },
    /// List clients (never tokens — hashes only)
    List,
    /// Revoke by name or id
    Revoke { name_or_id: String },
}
