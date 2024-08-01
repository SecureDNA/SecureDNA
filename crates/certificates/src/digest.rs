// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Display;

use serde::Serialize;

pub trait Digestible: Sized + Serialize {
    type Digest: Serialize + Display + From<Self>;
    fn into_digest(self) -> Self::Digest {
        self.into()
    }
}
