// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificate_tests::load_root_public_keys;
use certificates::{Exemption, Infrastructure, Manufacturer};

pub static TEST_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test/certs");

load_root_public_keys! {
    TEST_DIR;
    TEST_INFRASTRUCTURE_ROOT, Infrastructure, "infrastructure-roots/infrastructure-root.cert";
    TEST_MANUFACTURER_ROOT, Manufacturer, "manufacturer-roots/manufacturer-root.cert";
    TEST_EXEMPTION_ROOT, Exemption, "exemption-roots/exemption-root.cert";
}
