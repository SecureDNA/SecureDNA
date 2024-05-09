// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::key_traits::HasAssociatedKey;
use crate::{Id, Issued, PublicKey};

#[derive(Default)]
pub struct RevocationList {
    public_keys: Vec<PublicKey>,
    request_ids: Vec<Id>,
    issuance_ids: Vec<Id>,
}

impl RevocationList {
    pub fn with_public_key(mut self, public_key: PublicKey) -> Self {
        self.public_keys.push(public_key);
        self
    }

    pub fn with_request_id(mut self, request_id: Id) -> Self {
        self.request_ids.push(request_id);
        self
    }

    pub fn with_issuance_id(mut self, issuance_id: Id) -> Self {
        self.issuance_ids.push(issuance_id);
        self
    }

    pub fn item_id_has_been_revoked<I: Issued>(&self, item: &I) -> bool {
        self.issuance_ids.contains(item.issuance_id())
            || self.request_ids.contains(item.request_id())
    }

    pub fn item_id_or_public_key_has_been_revoked<I: Issued + HasAssociatedKey>(
        &self,
        item: &I,
    ) -> bool {
        self.item_id_has_been_revoked(item) || self.public_keys.contains(item.public_key())
    }

    pub fn public_key_has_been_revoked(&self, public_key: &PublicKey) -> bool {
        self.public_keys.contains(public_key)
    }
}
