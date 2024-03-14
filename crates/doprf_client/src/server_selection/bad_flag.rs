// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::{atomic, Arc};

/// Whether this server has been marked bad due to an error, and shouldn't be used.
/// Can only be set, to unset, the server must be re-qualified in a new round of server selection.
///
/// This flag is internally mutable, inside an `Arc` so that clones preserve the reference to the same flag.
/// We want internal mutability so that flagging a single server as bad does not require waiting for all *reads*
/// of the server selection to be finished. We're fine with flagging the servers used by an in-progress request
/// as bad, since badness is a ratchet.
#[derive(Default, Debug, Clone)]
pub struct ServerBadFlag(Arc<atomic::AtomicBool>);

// we're a bit cavalier here about loading the atomic bool into a regular bool--this should
// be fine, since the worst that can happen on a slightly out-of-date read is that a request
// is made to a bad server, which will just fail and cause a retry. it will never cause a bad
// server to be marked good, since ServerBadFlag can't be unmarked.

impl ServerBadFlag {
    pub fn mark_bad(&self) {
        self.0.store(true, atomic::Ordering::SeqCst);
    }

    pub fn is_bad(&self) -> bool {
        self.0.load(atomic::Ordering::SeqCst)
    }
}

impl PartialEq for ServerBadFlag {
    fn eq(&self, other: &Self) -> bool {
        self.is_bad() == other.is_bad()
    }
}

impl Eq for ServerBadFlag {}
