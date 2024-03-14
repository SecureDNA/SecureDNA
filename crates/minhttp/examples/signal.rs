// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
use std::cell::Cell;
use std::time::Duration;

use tokio::time::sleep;

use minhttp::signal::{fast_shutdown_requested, graceful_shutdown_requested};

// Prints repeating messages until a graceful shutdown (CTRL-C) is requested.
// Graceful shutdowns only take effect right before "Beep".
// Fast shutdowns (SIGTERMs, multiple CTRL-Cs, etc) should happen instantly
// yet in a relatively controlled manner (printing "Ended" instead of aborting).
#[tokio::main]
async fn main() {
    println!("Started");

    let keep_running = Cell::new(true);

    let run = async {
        while keep_running.get() {
            println!("Beep!");
            sleep(Duration::from_secs(1)).await;
            println!("Boop!");
            sleep(Duration::from_secs(1)).await;
            println!("Boppity!");
            sleep(Duration::from_secs(1)).await;
            println!("Bop!");
            sleep(Duration::from_secs(1)).await;
        }
        println!("Graceful shutdown complete.");
    };

    let graceful_shutdown = async {
        graceful_shutdown_requested().await;
        println!("Graceful shutdown requested...");
        keep_running.set(false);
    };

    let run_until_gracefully_shutdown = async { tokio::join!(run, graceful_shutdown) };

    tokio::select! {
        _ = run_until_gracefully_shutdown => {}
        _ = fast_shutdown_requested() => println!("Fast shutdown requested..."),
    };

    println!("Ended");
}
