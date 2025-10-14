// Copyright 2021-2025 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#[path = "test_common.rs"]
mod test_common;
#[cfg(feature = "cert_tests")]
mod tests {
    use certificate_tests::validate_public_and_private_cert_files;
    use certificates::{Exemption, Infrastructure, Manufacturer};

    use super::test_common::tests::{
        TEST_DIR, TEST_EXEMPTION_ROOT, TEST_INFRASTRUCTURE_ROOT, TEST_MANUFACTURER_ROOT,
    };

    validate_public_and_private_cert_files!(validate_test_infrastructure_certs,
        TEST_DIR, TEST_INFRASTRUCTURE_ROOT, Infrastructure;
        "root", "intermediate", "int-int", "leaf"
    );
    validate_public_and_private_cert_files!(validate_test_manufacturer_certs,
        TEST_DIR, TEST_MANUFACTURER_ROOT, Manufacturer;
        "root", "intermediate", "int-int", "leaf"
    );
    validate_public_and_private_cert_files!(validate_test_exemption_certs,
        TEST_DIR, TEST_EXEMPTION_ROOT, Exemption;
        "root", "intermediate", "int-int", "leaf"
    );
}
