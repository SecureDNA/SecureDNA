// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::future::Future;

use tokio::sync::{watch, Mutex};

/// Uses tokio::sync::watch to coordinate access to a refreshable `T`.
/// `T` must be clone, and will be cloned relatively often, so it's advisable
/// to wrap it in an `Arc` if it uses the heap.
#[derive(Debug)]
pub struct Refreshable<T: Clone> {
    tx: watch::Sender<T>,
    rx: watch::Receiver<T>,
    refreshing: Mutex<()>,
}

impl<T: Clone> Refreshable<T> {
    /// Construct a new `Refreshable` with an initial `T`.
    pub fn new(value: T) -> Self {
        let (tx, rx) = watch::channel(value);
        Self {
            tx,
            rx,
            refreshing: Mutex::new(()),
        }
    }

    /// Initiate a background refresh using `populate`: if a refresh is not already
    /// in progress, `populate` will be called, and the resulting value will be
    /// slotted into the channel.
    ///
    /// This function will fail if `populate` fails.
    #[allow(dead_code)] // currently unused in wasm build
    pub async fn background_refresh<F, E>(&self, mut populate: impl FnMut() -> F) -> Result<(), E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let _lock = match self.refreshing.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(()), // don't try to background refresh if someone already is
        };
        let value = populate().await?;
        self.tx.send_replace(value);
        Ok(())
    }

    /// Helper to wait for an `accept`able value from the channel.
    async fn wait_for<U>(&self, mut accept: impl FnMut(T) -> Option<U>) -> U {
        let mut rx = self.rx.clone();
        let mut accepted: Option<U> = None;
        // unwrap: this returns an error if the sender is closed, which means the type has
        // been dropped, which isn't possible since we have a reference to self here
        rx.wait_for(|v| {
            accepted = accept(v.clone());
            accepted.is_some()
        })
        .await
        .unwrap();
        accepted.unwrap()
    }

    /// Wait until a valid value (accepted by `accept`) is available,
    /// then return the transformation of that value produced by `accept`.
    /// If the current value held in the channel is not `accept`able, then
    /// `populate` will be used to generate a new one.
    ///
    /// Note that both `accept` and `populate` will be called multiple times,
    /// and `accept` may be called more than once with a valid value.
    ///
    /// This function will fail if `populate()` fails.
    pub async fn accept_or<U, E, F>(
        &self,
        mut accept: impl FnMut(T) -> Option<U> + Clone,
        mut populate: impl FnMut() -> F,
    ) -> Result<U, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        // try to get the latest valid value
        let latest_valid = self.wait_for(accept.clone());

        // loop continuously trying to refresh the value, only stopping on error
        // or indirectly when we successfully refresh (which will fill the channel,
        // allowing `latest_valid` to be selected)
        let refresh = async {
            let mut rx = self.rx.clone();
            loop {
                let _lock = self.refreshing.lock().await;
                // The value may have been populated between when we waited
                // for it to be empty and grabbed the lock...
                // double-check that it's really necessary to populate it.
                if accept(rx.borrow_and_update().clone()).is_some() {
                    continue;
                }
                let value = populate().await?;
                self.tx.send_replace(value);
            }
        };

        tokio::select! {
            v = latest_valid => Ok(v),
            err = refresh => err,
        }
    }
}
