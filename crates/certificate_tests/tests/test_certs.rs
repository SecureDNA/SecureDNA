// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use certificate_tests::validate_public_and_private_cert_files;
use certificates::{Exemption, Infrastructure, Manufacturer};

#[path = "test_common.rs"]
mod test_common;

use test_common::{
    TEST_DIR, TEST_EXEMPTION_ROOT, TEST_INFRASTRUCTURE_ROOT, TEST_MANUFACTURER_ROOT,
};

validate_public_and_private_cert_files!(TEST_DIR, TEST_INFRASTRUCTURE_ROOT, Infrastructure; "root", "intermediate", "int-int", "leaf");
validate_public_and_private_cert_files!(TEST_DIR, TEST_MANUFACTURER_ROOT, Manufacturer; "root", "intermediate", "int-int", "leaf");
validate_public_and_private_cert_files!(TEST_DIR, TEST_EXEMPTION_ROOT, Exemption; "root", "intermediate", "int-int", "leaf");
