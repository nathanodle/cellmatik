//! Token admin CLI (spec §2): 64-hex random tokens, SHA-256 at rest,
//! plaintext shown exactly once. Runs against the live DB (WAL handles
//! concurrent service access).
//!
//! SECURITY (spec §7): tokens from the OS CSPRNG; never logged; hash-only
//! at rest; revoke is idempotent.

use crate::config::Config;
use crate::db::Db;

pub enum TokenAction {
    Add { name: String },
    List,
    Revoke { name_or_id: String },
}

/// Run one admin action against the configured DB, print to stdout.
pub fn run(cfg: &Config, action: TokenAction) -> anyhow::Result<()> {
    let db = Db::open(&cfg.db_path, &cfg.media_dir)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        match action {
            TokenAction::Add { name } => {
                let token = generate_token();
                let hash = sha256_hex(&token);
                let row = db.add_client(&name, &hash).await?;
                // Shown exactly once; never logged.
                println!("client: {} (id {})", row.name, row.id);
                println!("token:  {token}");
                println!("store it now — it is not recoverable");
            }
            TokenAction::List => {
                let clients = db.list_clients().await?;
                if clients.is_empty() {
                    println!("no clients");
                }
                for c in clients {
                    let state = match c.revoked_at {
                        Some(_) => "revoked",
                        None => "active",
                    };
                    println!("{:>4}  {:<24} {}", c.id, c.name, state);
                }
            }
            TokenAction::Revoke { name_or_id } => {
                let ok = db.revoke_client(&name_or_id).await?;
                if ok {
                    println!("revoked: {name_or_id}");
                } else {
                    println!("no active client matched: {name_or_id}");
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    })
}

/// 32 bytes from the OS RNG → 64 hex chars (256-bit, spec §2).
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// SHA-256 hex of the token — the only stored form.
pub fn sha256_hex(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}
