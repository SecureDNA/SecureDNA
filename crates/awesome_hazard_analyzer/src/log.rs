// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Setup for using `tracing` for loggin in AHA. Eventually, the rest of the project will likely
//! move to `tracing`, at that time all or part of this module may be moved to a more centralized
//! module.

use anyhow::{bail, Result};
use tracing::{info, Level};
use tracing_subscriber::{
    filter,
    fmt::{format::FmtSpan, time::OffsetTime, Layer},
    prelude::*,
};

pub fn log_level_from_count(verbosity_level: u8) -> Result<filter::LevelFilter> {
    Ok(match verbosity_level {
        0 => filter::LevelFilter::INFO,
        1 => filter::LevelFilter::DEBUG,
        2 => filter::LevelFilter::TRACE,
        _ => bail!("only log levels up to TRACE supported"),
    })
}

/// Note: time offset should be initialized before any threading occurs, see
/// <https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/time/struct.OffsetTime.html>
pub fn init_log(log_level: filter::LevelFilter, time_offset: time::UtcOffset) -> Result<()> {
    let time_fmt = time::format_description::well_known::Iso8601::DEFAULT;
    let timer = OffsetTime::new(time_offset, time_fmt);

    let layer = Layer::new()
        .with_target(false)
        .with_timer(timer)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_ansi(false);

    let filter = filter::Targets::new()
        .with_targets(vec![("awesome_hazard_analyzer", log_level)])
        .with_default(Level::WARN);

    tracing_subscriber::registry()
        .with(layer.with_writer(std::io::stdout).with_filter(filter))
        .try_init()?;

    info!("Logging at level {}", log_level);

    Ok(())
}
