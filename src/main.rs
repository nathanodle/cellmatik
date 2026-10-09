//! cellmatik — single-modem cellular gateway (spec: sms-api-spec.md).
//!
//! Wiring: config → db → modem (serial worker) → wwan (bearer) → mms →
//! voice → webhook dispatcher → axum serve. Background loops: retention
//! sweep, VP-deadline failer, staging flush. Graceful shutdown on
//! ctrl-c/SIGTERM.
//!
//! SECURITY (spec §7): tracing with env filter; no secret ever logged;
//! startup errors name the offending config key.

mod api;
mod cli;
mod config;
mod db;
mod envelope;
mod mms;
mod modem;
mod pdu;
mod tokens;
mod types;
mod voice;
mod wbxml;
mod wwan;

use chrono::Timelike;
use clap::Parser;

fn main() -> anyhow::Result<()> {
    let cli = cli::Cli::parse();
    let cfg = config::Config::load(&cli.config)?;

    match cli.cmd {
        Some(cli::Command::Token { action }) => {
            let action = match action {
                cli::TokenAction::Add { name } => tokens::TokenAction::Add { name },
                cli::TokenAction::List => tokens::TokenAction::List,
                cli::TokenAction::Revoke { name_or_id } => {
                    tokens::TokenAction::Revoke { name_or_id }
                }
            };
            tokens::run(&cfg, action)
        }
        None => run_service(cfg),
    }
}

fn run_service(cfg: config::Config) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move { service(cfg).await })
}

async fn service(cfg: config::Config) -> anyhow::Result<()> {
    let cfg = std::sync::Arc::new(cfg);

    let db = db::Db::open(&cfg.db_path, &cfg.media_dir)?;
    tracing::info!(target: "cellmatik", db = ?cfg.db_path, "db open");

    let events = envelope::EventBus::new();

    // Modem: fail fast with a clear error if the serial path is missing.
    let modem_cfg = modem::ModemConfig {
        serial_path: cfg.serial_path.clone(),
        profile: cfg.profile,
        queue_limit: cfg.queue_limit,
        submit_retries: cfg.submit_retries,
        retry_interval_s: cfg.retry_interval_s,
        csmp_vp: cfg.csmp_vp,
        max_segments: cfg.max_segments,
        gpio_power_cycle: cfg.recovery.gpio_power_cycle,
        pwrkey_gpio: cfg.recovery.pwrkey_gpio,
        recovery_backoff_s: cfg.recovery.backoff_s,
        mms_enabled: cfg.mms.enabled,
    };
    let modem = modem::Modem::spawn(modem_cfg, db.clone(), events.clone())?;

    // Bearer: cheap when mms disabled; owns usb0 per manage mode (§5).
    let wwan = wwan::Wwan::spawn(
        wwan::WwanConfig {
            manage: cfg.mms.manage,
            enabled: cfg.mms.enabled,
            interface: "usb0".to_string(),
            proxy: cfg.mms.proxy.clone(),
            user_agent: cfg.mms.ua.clone(),
        },
        events.clone(),
    );

    let mms = mms::Mms::spawn(cfg.clone(), db.clone(), wwan.clone(), modem.clone(), events.clone());

    let voice = voice::Voice::spawn(
        modem.clone(),
        db.clone(),
        events.clone(),
        voice::VoiceCfg {
            #[cfg(feature = "audio")]
            audio_device: cfg.voice.audio_device.clone(),
            #[cfg(feature = "audio")]
            audio_frame_ms: cfg.voice.audio_frame_ms,
            audio_grace_s: cfg.voice.audio_grace_s,
            ring_timeout_s: cfg.voice.ring_timeout_s,
            max_call_duration_s: cfg.voice.max_call_duration_s,
            dtmf_detection: cfg.voice.dtmf_detection,
            voice_supported: cfg.profile.voice_supported(),
        },
    );

    envelope::spawn_webhook_dispatcher(db.clone(), events.clone(), cfg.clone());

    // Background loops.
    spawn_retention_sweep(db.clone(), cfg.clone());
    spawn_vp_deadline_failer(db.clone());
    spawn_staging_flush(db.clone(), events.clone());

    let state: api::SharedState = std::sync::Arc::new(api::AppState {
        db,
        modem: modem.clone(),
        voice,
        mms,
        wwan: wwan.clone(),
        cfg: cfg.clone(),
        events,
        started: std::time::Instant::now(),
    });
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    tracing::info!(target: "cellmatik", listen = %cfg.listen, "cellmatik up (v{})", types::PKG_VERSION);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    // graceful teardown: port thread observes the flag within one read
    // budget; wwan poller exits on notify.
    modem.stop().await;
    wwan.stop().await;
    tracing::info!(target: "cellmatik", "shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.ok() };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

/// Nightly retention sweep at retention.sweep_hour (§4/§6).
fn spawn_retention_sweep(db: db::Db, cfg: std::sync::Arc<config::Config>) {
    tokio::spawn(async move {
        let mut last_run_day = String::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            if cfg.retention.mode != config::RetentionMode::Sweep {
                continue;
            }
            let now = chrono::Utc::now();
            let day = now.format("%Y-%m-%d").to_string();
            if now.hour() == cfg.retention.sweep_hour && last_run_day != day {
                last_run_day = day.clone();
                match db
                    .sweep(cfg.retention.inbox_days, cfg.retention.outbox_days, cfg.retention.calls_days)
                    .await
                {
                    Ok(()) => tracing::info!(target: "cellmatik::retention", day = %day, "sweep done"),
                    Err(e) => tracing::warn!(target: "cellmatik::retention", error = %e, "sweep failed"),
                }
            }
        }
    });
}

/// VP-deadline failer: no CDS by the VP-decoded deadline →
/// failed/no_delivery_report (spec §3).
fn spawn_vp_deadline_failer(db: db::Db) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            tick.tick().await;
            match db.expire_vp_deadlines().await {
                Ok(expired) => {
                    for row in expired {
                        tracing::info!(target: "cellmatik::outbox", id = row.id, "vp deadline expired → failed/no_delivery_report");
                    }
                }
                Err(e) => tracing::warn!(target: "cellmatik::outbox", error = %e, "vp expiry check failed"),
            }
        }
    });
}

/// Staging flush every 60 s: concat groups older than 300 s surface as
/// visible partial messages (spec §5).
fn spawn_staging_flush(db: db::Db, events: envelope::EventBus) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tick.tick().await;
            match db.flush_stale_staging(300).await {
                Ok(rows) => {
                    for row in rows {
                        let item = envelope::inbox_item_json(&row);
                        events.publish(types::Event::message(item));
                    }
                }
                Err(e) => tracing::warn!(target: "cellmatik::inbox", error = %e, "staging flush failed"),
            }
        }
    });
}
