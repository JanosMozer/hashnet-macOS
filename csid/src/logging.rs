use std::path::PathBuf;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    let log_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Library/Logs/Hashnet");

    std::fs::create_dir_all(&log_dir)?;

    let file_appender = tracing_appender::rolling::daily(&log_dir, "csid.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let fmt_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_target(true)
        .with_level(true)
        .with_ansi(false);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("csid=info,csi_core=info,warn"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(guard)
}
