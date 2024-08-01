// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{collections::HashMap, path::PathBuf};

use anyhow::Context;
use chrono::{Duration, NaiveDate, NaiveTime, TimeZone, Utc};
use clap::{ArgAction, Parser};
use tracing::{debug, info, warn, Level};

use certificates::{Id, SynthesizerTokenGroup, TokenBundle};
use hdbserver::event_store as hdb_event_store;
use keyserver::event_store as ks_event_store;
use persistence::{Connection, OffsetDateTime};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser)]
struct Opts {
    #[arg(
        short,
        long,
        help = "Suppress non-error output and set the log level to WARN."
    )]
    quiet: bool,

    #[arg(
        short,
        long,
        action = ArgAction::Count,
        help = "Increase verbosity level, can be used multiple times."
    )]
    verbose: u8,

    #[clap(help = "Path to the event_store SQLite DB file")]
    db_path: PathBuf,

    #[clap(flatten)]
    db_kind: DbKind,

    #[clap(
        long,
        short = 's',
        help = "UTC start date for the statistics (inclusive, defaults to 30 days ago)"
    )]
    start_date: Option<NaiveDate>,

    #[clap(
        long,
        short = 'e',
        help = "UTC end date for the statistics (inclusive, defaults to today)"
    )]
    end_date: Option<NaiveDate>,
}

#[derive(Debug, clap::Args)]
#[group(required = true, multiple = false)]
struct DbKind {
    #[arg(
        long,
        short = 'k',
        action = ArgAction::SetTrue,
        help = "Indicates `db_path` uses the keyserver schema.",
    )]
    keyserver: bool,

    #[arg(
        long,
        short = 'd',
        action = ArgAction::SetTrue,
        help = "Indicates `db_path` uses the hdbserver schema.",
    )]
    hdbserver: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::parse();

    let subscriber = FmtSubscriber::builder()
        .with_writer(std::io::stderr)
        .with_max_level(match (opts.quiet, opts.verbose) {
            (true, _) => Level::WARN,
            (false, 0) => Level::INFO,
            (false, 1) => Level::DEBUG,
            (false, _) => Level::TRACE,
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let conn = Connection::open(&opts.db_path).await?;
    let conn = if opts.db_kind.keyserver {
        StatinableConnection::Keyserver(conn)
    } else {
        StatinableConnection::Hdbserver(conn)
    };
    debug!("Opened {} event store at {:?}", conn.name(), opts.db_path);

    let start_date = opts
        .start_date
        .unwrap_or_else(|| Utc::now().date_naive() - Duration::days(30));
    let end_date = opts.end_date.unwrap_or(Utc::now().date_naive());

    info!("Gathering statistics from {start_date} - {end_date} UTC");

    let start_date = chrono_date_to_time(start_date);
    let end_date = chrono_date_to_time(end_date);

    let mut records = Records::new();
    for (id, token) in conn
        .query_certs()
        .await
        .context("Unable to query certificates")?
        .into_iter()
    {
        records.add_manufacturer_id(id, token);
    }
    info!(
        "Found {} manufacturer certificate id(s)",
        records.manufacturers.len()
    );

    for (dt, id, bp) in conn
        .query_bp_per_day_per_client(start_date, end_date)
        .await?
    {
        let date = time_to_chrono_date(dt);
        records.add_bp(date, &id, bp)?;
    }

    for (dt, id, orders) in conn
        .query_orders_per_day_per_client(start_date, end_date)
        .await?
    {
        let date = time_to_chrono_date(dt);
        records.add_orders(date, &id, orders)?;
    }

    for (dt, id, exceedances) in conn
        .query_exceedances_per_day_per_client(start_date, end_date)
        .await?
    {
        let date = time_to_chrono_date(dt);
        records.add_exceedances(date, &id, exceedances)?;
    }

    let rows = records.rows();
    info!("{} rows generated", rows.len());

    println!("date\tmanufacturer_domain\tbp\torders\texceedances");
    for (date, domain, entry) in rows {
        let escaped_domain = domain.0.replace('\t', "    ").replace('\n', " ");
        let RecordEntry {
            bp,
            orders,
            exceedances,
        } = entry;
        println!("{date}\t{escaped_domain}\t{bp}\t{orders}\t{exceedances}");
    }

    Ok(())
}

fn chrono_date_to_time(date: NaiveDate) -> OffsetDateTime {
    let dt = date
        .and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap())
        .and_utc();
    OffsetDateTime::from_unix_timestamp(dt.timestamp()).unwrap()
}

fn time_to_chrono_date(dt: OffsetDateTime) -> NaiveDate {
    Utc.timestamp_opt(dt.unix_timestamp(), 0)
        .unwrap()
        .date_naive()
}

#[derive(Debug, Clone, Default)]
struct Records {
    manufacturers: HashMap<Id, ManufacturerDomain>,
    entries: HashMap<(NaiveDate, ManufacturerDomain), RecordEntry>,
}

impl Records {
    fn new() -> Self {
        Self::default()
    }

    fn add_manufacturer_id(&mut self, id: Id, token: TokenBundle<SynthesizerTokenGroup>) {
        let manufacturer = ManufacturerDomain(token.token.manufacturer_domain().to_owned());
        match self.manufacturers.get(&id) {
            None => {
                self.manufacturers.insert(id, manufacturer);
            }
            Some(existing) if existing == &manufacturer => { /* ignore */ }
            Some(existing) => {
                // keep existing domain in case of conflict
                warn!(
                    "Conflicting manufacturer domains for id {id}: {} and {}, using {}",
                    manufacturer.0, existing.0, existing.0
                );
            }
        }
    }

    fn manufacturer(&self, id: &Id) -> anyhow::Result<&ManufacturerDomain> {
        self.manufacturers
            .get(id)
            .ok_or(anyhow::anyhow!("Id {id} not found in certs table"))
    }

    fn add_bp(&mut self, date: NaiveDate, id: &Id, bp: u64) -> anyhow::Result<()> {
        self.entries
            .entry((date, self.manufacturer(id)?.clone()))
            .or_default()
            .bp += bp;
        Ok(())
    }

    fn add_orders(&mut self, date: NaiveDate, id: &Id, orders: u64) -> anyhow::Result<()> {
        self.entries
            .entry((date, self.manufacturer(id)?.clone()))
            .or_default()
            .orders += orders;
        Ok(())
    }

    fn add_exceedances(
        &mut self,
        date: NaiveDate,
        id: &Id,
        exceedances: u64,
    ) -> anyhow::Result<()> {
        self.entries
            .entry((date, self.manufacturer(id)?.clone()))
            .or_default()
            .exceedances += exceedances;
        Ok(())
    }

    fn rows(self) -> Vec<(NaiveDate, ManufacturerDomain, RecordEntry)> {
        let mut rows = self
            .entries
            .into_iter()
            .map(|((date, domain), entry)| (date, domain, entry))
            .collect::<Vec<_>>();
        rows.sort_unstable();
        rows
    }
}

#[derive(Debug, Clone, PartialEq, Eq, std::hash::Hash, PartialOrd, Ord)]
struct ManufacturerDomain(String);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct RecordEntry {
    bp: u64,
    orders: u64,
    exceedances: u64,
}

enum StatinableConnection {
    Keyserver(Connection),
    Hdbserver(Connection),
}

impl StatinableConnection {
    fn name(&self) -> &'static str {
        match self {
            StatinableConnection::Keyserver(_) => "keyserver",
            StatinableConnection::Hdbserver(_) => "hdbserver",
        }
    }

    async fn query_certs(&self) -> anyhow::Result<HashMap<Id, TokenBundle<SynthesizerTokenGroup>>> {
        match self {
            StatinableConnection::Keyserver(c) => ks_event_store::query_certs(c)
                .await
                .context("Unable to query keyserver certs"),
            StatinableConnection::Hdbserver(c) => hdb_event_store::query_certs(c)
                .await
                .context("Unable to query hdbserver certs"),
        }
    }

    async fn query_bp_per_day_per_client(
        &self,
        start_date: OffsetDateTime,
        end_date: OffsetDateTime,
    ) -> anyhow::Result<impl Iterator<Item = (OffsetDateTime, Id, u64)>> {
        let result = match self {
            StatinableConnection::Keyserver(c) => {
                ks_event_store::query_bp_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query keyserver bp per client")?
            }
            StatinableConnection::Hdbserver(c) => {
                hdb_event_store::query_bp_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query hdbserver bp per client")?
            }
        };
        Ok(result.into_iter().map(|(dt, id, bp)| (dt.into(), id, bp)))
    }

    async fn query_orders_per_day_per_client(
        &self,
        start_date: OffsetDateTime,
        end_date: OffsetDateTime,
    ) -> anyhow::Result<impl Iterator<Item = (OffsetDateTime, Id, u64)>> {
        let result = match self {
            StatinableConnection::Keyserver(c) => {
                ks_event_store::query_orders_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query keyserver orders per client")?
            }
            StatinableConnection::Hdbserver(c) => {
                hdb_event_store::query_orders_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query hdbserver orders per client")?
            }
        };
        Ok(result
            .into_iter()
            .map(|(dt, id, orders)| (dt.into(), id, orders)))
    }

    async fn query_exceedances_per_day_per_client(
        &self,
        start_date: OffsetDateTime,
        end_date: OffsetDateTime,
    ) -> anyhow::Result<impl Iterator<Item = (OffsetDateTime, Id, u64)>> {
        let result = match self {
            StatinableConnection::Keyserver(c) => {
                ks_event_store::query_exceedances_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query keyserver exceedances per client")?
            }
            StatinableConnection::Hdbserver(c) => {
                hdb_event_store::query_exceedances_per_day_per_client(c, start_date, end_date)
                    .await
                    .context("Unable to query hdbserver exceedances per client")?
            }
        };
        Ok(result.into_iter().map(|(dt, id, exs)| (dt.into(), id, exs)))
    }
}
