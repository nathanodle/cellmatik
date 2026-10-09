//! TOML config (spec §6) — all knobs with spec defaults, hard validation.
//! Any combination that would run degraded or unsafe silently fails load.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModemProfile {
    Rm520n,
    Sim7600,
}

impl ModemProfile {
    /// Voice-capable modems; RM520N-GL has no audio path (spec §5).
    pub fn voice_supported(self) -> bool {
        match self {
            ModemProfile::Rm520n => false,
            ModemProfile::Sim7600 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmsManage {
    Cellmatik,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionMode {
    Sweep,
    Manual,
    Keep,
}

#[derive(Debug, Clone)]
pub struct VoiceCfg {
    /// ALSA name of the USB adapter; consumed only by audio builds.
    #[cfg(feature = "audio")]
    pub audio_device: String,
    pub audio_codec: String,
    pub audio_frame_ms: u32,
    pub audio_grace_s: u64,
    pub ring_timeout_s: u64,
    pub max_call_duration_s: u64,
    pub dtmf_detection: bool,
}

#[derive(Debug, Clone)]
pub struct RetentionCfg {
    pub mode: RetentionMode,
    pub sweep_hour: u32,
    pub inbox_days: u64,
    pub outbox_days: u64,
    pub calls_days: u64,
}

#[derive(Debug, Clone)]
pub struct RecoveryCfg {
    pub gpio_power_cycle: bool,
    pub pwrkey_gpio: u32,
    pub backoff_s: u64,
}

#[derive(Debug, Clone)]
pub struct MmsCfg {
    pub enabled: bool,
    pub manage: MmsManage,
    pub apn: String,
    pub mmsc_url: String,
    pub proxy: Option<String>,
    pub ua: String,
    pub max_bytes: usize,
    pub delivery_ack: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: String,
    pub db_path: PathBuf,
    pub media_dir: PathBuf,
    pub serial_path: String,
    pub profile: ModemProfile,
    pub queue_limit: usize,
    pub webhook_timeout_s: u64,
    pub heartbeat_s: u64,
    pub default_delivery_report: bool,
    pub stale_after_s: u64,
    pub submit_retries: u32,
    pub retry_interval_s: u64,
    pub max_segments: u8,
    pub csmp_vp: u8,
    pub voice: VoiceCfg,
    pub retention: RetentionCfg,
    pub recovery: RecoveryCfg,
    pub mms: MmsCfg,
}

// ---- serde file shape (flat + sections, spec §6) ----

#[derive(serde::Deserialize)]
struct File {
    listen: Option<String>,
    db_path: Option<String>,
    media_dir: Option<String>,
    serial_path: Option<String>,
    modem_profile: Option<String>,
    queue_limit: Option<usize>,
    webhook_timeout_s: Option<u64>,
    heartbeat_s: Option<u64>,
    default_delivery_report: Option<bool>,
    stale_after_s: Option<u64>,
    submit_retries: Option<u32>,
    retry_interval_s: Option<u64>,
    max_segments: Option<u8>,
    csmp_vp: Option<u8>,
    voice: Option<VoiceFile>,
    retention: Option<RetentionFile>,
    recovery: Option<RecoveryFile>,
    mms: Option<MmsFile>,
}

#[derive(serde::Deserialize)]
struct VoiceFile {
    #[cfg(feature = "audio")]
    audio_device: Option<String>,
    audio_codec: Option<String>,
    audio_frame_ms: Option<u32>,
    audio_grace_s: Option<u64>,
    ring_timeout_s: Option<u64>,
    max_call_duration_s: Option<u64>,
    dtmf_detection: Option<bool>,
}

#[derive(serde::Deserialize)]
struct RetentionFile {
    mode: Option<String>,
    sweep_hour: Option<u32>,
    inbox_retention_days: Option<u64>,
    outbox_retention_days: Option<u64>,
    calls_retention_days: Option<u64>,
}

#[derive(serde::Deserialize)]
struct RecoveryFile {
    gpio_power_cycle: Option<bool>,
    pwrkey_gpio: Option<u32>,
    recovery_backoff_s: Option<u64>,
}

#[derive(serde::Deserialize)]
struct MmsFile {
    enabled: Option<bool>,
    manage_interface: Option<String>,
    apn: Option<String>,
    mmsc_url: Option<String>,
    proxy: Option<String>,
    ua: Option<String>,
    max_bytes: Option<usize>,
    mms_delivery_ack: Option<bool>,
}

impl Config {
    /// Load and validate. Validation failures are hard errors with the
    /// offending key named — never run degraded silently (spec §7 spirit).
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("config read {path:?}: {e}"))?;
        let f: File = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("config parse {path:?}: {e}"))?;

        let db_path = PathBuf::from(f.db_path.unwrap_or_else(|| "/var/lib/cellmatik/cellmatik.db".into()));
        let media_dir = match f.media_dir {
            Some(m) => PathBuf::from(m),
            None => db_path
                .parent()
                .map(|p| p.join("media"))
                .unwrap_or_else(|| PathBuf::from("media")),
        };

        let profile = match f.modem_profile.as_deref().unwrap_or("rm520n") {
            "rm520n" => ModemProfile::Rm520n,
            "sim7600" => ModemProfile::Sim7600,
            other => anyhow::bail!("config: modem_profile {other:?} not recognized (rm520n|sim7600)"),
        };

        let retention_mode = match f.retention.as_ref().and_then(|r| r.mode.as_deref()).unwrap_or("sweep") {
            "sweep" => RetentionMode::Sweep,
            "manual" => RetentionMode::Manual,
            "none" => RetentionMode::Keep,
            other => anyhow::bail!("config: retention.mode {other:?} not recognized (sweep|manual|none)"),
        };

        let manage = match f.mms.as_ref().and_then(|m| m.manage_interface.as_deref()).unwrap_or("cellmatik") {
            "cellmatik" => MmsManage::Cellmatik,
            "host" => MmsManage::Host,
            other => anyhow::bail!("config: mms.manage_interface {other:?} not recognized (cellmatik|host)"),
        };

        let vf = f.voice.unwrap_or_default();
        let voice = VoiceCfg {
            #[cfg(feature = "audio")]
            audio_device: vf.audio_device.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "default".into()),
            audio_codec: vf.audio_codec.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "g711u".into()),
            audio_frame_ms: vf.audio_frame_ms.unwrap_or(20),
            audio_grace_s: vf.audio_grace_s.unwrap_or(5),
            ring_timeout_s: vf.ring_timeout_s.unwrap_or(30),
            max_call_duration_s: vf.max_call_duration_s.unwrap_or(3600),
            dtmf_detection: vf.dtmf_detection.unwrap_or(true),
        };
        let retention = f.retention.map(|r| RetentionCfg {
            mode: retention_mode,
            sweep_hour: r.sweep_hour.unwrap_or(3),
            inbox_days: r.inbox_retention_days.unwrap_or(90),
            outbox_days: r.outbox_retention_days.unwrap_or(90),
            calls_days: r.calls_retention_days.unwrap_or(90),
        }).unwrap_or(RetentionCfg { mode: retention_mode, sweep_hour: 3, inbox_days: 90, outbox_days: 90, calls_days: 90 });
        let recovery = f.recovery.map(|r| RecoveryCfg {
            gpio_power_cycle: r.gpio_power_cycle.unwrap_or(true),
            pwrkey_gpio: r.pwrkey_gpio.unwrap_or(17),
            backoff_s: r.recovery_backoff_s.unwrap_or(300),
        }).unwrap_or(RecoveryCfg { gpio_power_cycle: true, pwrkey_gpio: 17, backoff_s: 300 });
        let mms = f.mms.map(|m| MmsCfg {
            enabled: m.enabled.unwrap_or(false),
            manage,
            apn: m.apn.unwrap_or_default(),
            mmsc_url: m.mmsc_url.unwrap_or_default(),
            proxy: m.proxy.filter(|p| !p.trim().is_empty()),
            ua: m.ua.unwrap_or_else(|| format!("cellmatik/{}", crate::types::PKG_VERSION)),
            max_bytes: m.max_bytes.unwrap_or(1_000_000),
            delivery_ack: m.mms_delivery_ack.unwrap_or(false),
        }).unwrap_or(MmsCfg { enabled: false, manage, apn: String::new(), mmsc_url: String::new(), proxy: None, ua: String::new(), max_bytes: 1_000_000, delivery_ack: false });

        let cfg = Config {
            listen: f.listen.unwrap_or_else(|| "0.0.0.0:8080".into()),
            db_path,
            media_dir,
            serial_path: f.serial_path.unwrap_or_else(|| "/dev/ttyUSB2".into()),
            profile,
            queue_limit: f.queue_limit.unwrap_or(32),
            webhook_timeout_s: f.webhook_timeout_s.unwrap_or(5),
            heartbeat_s: f.heartbeat_s.unwrap_or(20),
            default_delivery_report: f.default_delivery_report.unwrap_or(true),
            stale_after_s: f.stale_after_s.unwrap_or(120),
            submit_retries: f.submit_retries.unwrap_or(3),
            retry_interval_s: f.retry_interval_s.unwrap_or(60),
            max_segments: f.max_segments.unwrap_or(10),
            csmp_vp: f.csmp_vp.unwrap_or(167),
            voice,
            retention,
            recovery,
            mms,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.max_segments == 0 {
            anyhow::bail!("config: max_segments must be 1..=255 (got {})", self.max_segments);
        }
        if self.voice.audio_codec != "g711u" {
            anyhow::bail!(
                "config: voice.audio_codec must be \"g711u\" (the only supported codec, spec §4): got {:?}",
                self.voice.audio_codec
            );
        }
        if self.mms.enabled {
            if self.mms.apn.trim().is_empty() {
                anyhow::bail!("config: mms.enabled=true requires mms.apn (carrier data APN)");
            }
            if self.mms.mmsc_url.trim().is_empty() {
                anyhow::bail!("config: mms.enabled=true requires mms.mmsc_url");
            }
            if self.mms.mmsc_url.starts_with("https://") {
                anyhow::bail!("config: mms.mmsc_url must be http:// (carrier MMSCs are plain HTTP; no TLS stack by design)");
            }
            if self.mms.ua.trim().is_empty() {
                anyhow::bail!("config: mms.enabled=true requires mms.ua");
            }
        }
        if self.voice.audio_frame_ms < 10 || self.voice.audio_frame_ms > 60 {
            anyhow::bail!("config: voice.audio_frame_ms must be 10..=60 ms (got {})", self.voice.audio_frame_ms);
        }
        if self.listen.trim().is_empty() {
            anyhow::bail!("config: listen must not be empty");
        }
        Ok(())
    }
}

impl Default for VoiceFile {
    fn default() -> Self {
        VoiceFile {
            #[cfg(feature = "audio")]
            audio_device: Some("default".into()),
            audio_codec: Some("g711u".into()),
            audio_frame_ms: Some(20),
            audio_grace_s: Some(5),
            ring_timeout_s: Some(30),
            max_call_duration_s: Some(3600),
            dtmf_detection: Some(true),
        }
    }
}
