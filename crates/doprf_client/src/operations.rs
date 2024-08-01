// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::DoprfError;
use crate::instant::get_now;
use crate::progress::report_progress;
use doprf::active_security::ActiveSecurityKey;
use doprf::party::KeyserverId;
use doprf::prf::{HashPart, QueryStateSet};
use doprf::tagged::{HashTag, TaggedHash};
use packed_ristretto::{PackableRistretto, PackedRistrettos};

use shared_types::requests::RequestContext;
use tracing::debug;

#[cfg(target_arch = "wasm32")]
async fn spawn_blocking<F, R>(f: F) -> Result<R, ()>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    Ok(f())
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// What size of chunks the requests will be made in.
/// Each chunk incurs a network roundtrip, so it's good to have larger chunks,
/// but too large and we start spending too long in CPU-bound work without yielding often enough.
///
/// Chunks should go away completely once we switch to a streaming model
pub const CHUNK_SIZE_DEFAULT: usize = 10_000;

/// Make QueryStateSets for the given sequences. These are sent to the
/// keyservers instead of the sequences themselves (the keyservers are "blinded"
/// from seeing the original sequences).
///
/// Note: one QueryStateSet corresponds to many sequences (up to CHUNK_SIZE).
/// For example, given CHUNK_SIZE = 10,000, when this function is called with
/// 72,000 sequences, it returns a Vec of 8 QueryStateSets; the first seven
/// correspond to 10,000 sequences each, and the last one to the final chunk of
/// 2,000 sequences.
///
/// `sequences` cannot be empty, the method will panic if it is.
pub fn make_keyserver_querysets(
    request_ctx: &RequestContext,
    sequences: &[(HashTag, impl AsRef<str> + Sync)],
    num_required_keyshares: usize,
    target: &ActiveSecurityKey,
) -> QueryStateSet {
    let now = get_now();

    assert!(!sequences.is_empty());

    report_progress(request_ctx);

    // initial querystateset of hashes, blinds keyservers from seeing original sequences
    let querystates = QueryStateSet::from_iter(
        sequences.iter().map(|(t, w)| (*t, w.as_ref().as_bytes())),
        num_required_keyshares,
        target.clone(),
    );

    report_progress(request_ctx);

    let setup_duration = now.elapsed();
    debug!("Setting up done. Took: {:.2?}", setup_duration);
    querystates
}

/// Given a QueryStateSet, and a Vec of keyserver responses,
/// incorporate the responses into the querystate.
/// Then compute packed Ristretto hashes for the QueryStateSet.
/// The result is used to query HDB.
pub async fn incorporate_responses_and_hash<R>(
    request_ctx: &RequestContext,
    mut querystate: QueryStateSet,
    keyserver_responses: Vec<(KeyserverId, PackedRistrettos<HashPart>)>,
) -> Result<PackedRistrettos<R>, DoprfError>
where
    R: From<TaggedHash> + PackableRistretto + 'static,
    <R as PackableRistretto>::Array: Send + 'static,
{
    let now = get_now();
    report_progress(request_ctx);

    for (id, ks_pr) in keyserver_responses.into_iter() {
        let parts = ks_pr.iter_decoded().collect::<Result<Vec<HashPart>, _>>()?;

        querystate = spawn_blocking(move || -> Result<QueryStateSet, doprf::prf::QueryError> {
            querystate.incorporate_response(id, &parts)?;
            Ok(querystate) // hand back querystate for borrow-checking purposes
        })
        .await
        .expect("failed to join task")?;
    }

    let incorporating_duration = now.elapsed();
    debug!(
        "Incorporating keyserver answers done. Took: {:.2?}",
        incorporating_duration
    );

    let now = get_now();
    report_progress(request_ctx);
    let hash_values: PackedRistrettos<R> = spawn_blocking(move || {
        querystate
            .get_hash_values()
            .expect("error processing keyserver responses")
            .into_iter()
            .map(R::from)
            .collect()
    })
    .await
    .expect("could not join thread");

    let hash_duration = now.elapsed();
    debug!(
        "Calculating hashes with lagrange improvements done. Took: {:.2?}",
        hash_duration
    );

    report_progress(request_ctx);
    Ok(hash_values)
}
