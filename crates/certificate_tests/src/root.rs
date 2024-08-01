// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Creates a single instance of each root public key for each specified role by parsing the supplied certificates
#[macro_export]
macro_rules! load_root_public_keys {
    ($certs_dir:expr; $($public_key_name:ident, $role:ty, $path:expr);* $(;)?) => {
        $(
            pub static $public_key_name: ::once_cell::sync::Lazy<::certificates::PublicKey> = ::once_cell::sync::Lazy::new(|| {
                let root_cert_file = ::std::path::PathBuf::from($certs_dir).join($path);
                let root_cert = ::certificates::file::load_certificate_bundle_from_file::<$role>(&root_cert_file)
                    .expect("could not load root cert");

                *root_cert
                .get_lead_cert()
                .unwrap()
                .public_key()
            });
        )*
    };
}
