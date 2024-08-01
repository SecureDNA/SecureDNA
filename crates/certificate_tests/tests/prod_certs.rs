// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::path::PathBuf;

use certificate_tests::{load_root_public_keys, validate_public_cert_files};
use certificates::{Exemption, Infrastructure, Manufacturer};

pub static PROD_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs");

load_root_public_keys! {
    PROD_DIR;
    PROD_INFRASTRUCTURE_ROOT, Infrastructure, "infrastructure-roots/infrastructure-root.cert";
    PROD_MANUFACTURER_ROOT, Manufacturer, "manufacturer-roots/manufacturer-root.cert";
    PROD_EXEMPTION_ROOT, Exemption, "exemption-roots/exemption-root.cert";
}

validate_public_cert_files!(PROD_DIR, PROD_INFRASTRUCTURE_ROOT, Infrastructure; "root", "intermediate", "int-int", "leaf");
validate_public_cert_files!(PROD_DIR, PROD_MANUFACTURER_ROOT, Manufacturer; "root", "intermediate", "int-int", "leaf");
validate_public_cert_files!(PROD_DIR, PROD_EXEMPTION_ROOT, Exemption; "root", "intermediate", "int-int", "leaf");
