// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helpers to generate certificates for tests
//! TODO: should maybe be in `certificates`?

use certificates::{
    Builder, Certificate, CertificateBundle, DatabaseTokenGroup, DatabaseTokenRequest, Expiration,
    Infrastructure, IssuerAdditionalFields, KeyAvailable, KeyPair, KeyserverTokenGroup,
    KeyserverTokenRequest, Manufacturer, RequestBuilder, SynthesizerTokenGroup,
    SynthesizerTokenRequest, TokenBundle,
};
use doprf::party::KeyserverId;

#[derive(Debug, Clone)]
pub struct MakeCertsOptions {
    pub keyserver_id: KeyserverId,
}

impl Default for MakeCertsOptions {
    fn default() -> Self {
        Self {
            keyserver_id: KeyserverId::try_from(1).unwrap(),
        }
    }
}

pub struct CreatedCerts {
    pub infra_root_keypair: KeyPair,
    pub infra_root_cert: Certificate<Infrastructure, KeyAvailable>,
    pub infra_root_certbundle: CertificateBundle<Infrastructure>,
    pub keyserver_keypair: KeyPair,
    pub keyserver_tokenbundle: TokenBundle<KeyserverTokenGroup>,
    pub database_keypair: KeyPair,
    pub database_tokenbundle: TokenBundle<DatabaseTokenGroup>,
    pub manu_root_keypair: KeyPair,
    pub manu_root_cert: Certificate<Manufacturer, KeyAvailable>,
    pub manu_root_certbundle: CertificateBundle<Manufacturer>,
    pub synth_keypair: KeyPair,
    pub synth_tokenbundle: TokenBundle<SynthesizerTokenGroup>,
}

pub fn make_certs(options: MakeCertsOptions) -> CreatedCerts {
    let MakeCertsOptions { keyserver_id } = options;

    // make infrastructure root
    let infra_root_keypair = KeyPair::new_random();
    let infra_root_cert =
        RequestBuilder::<Infrastructure>::root_v1_builder(infra_root_keypair.public_key())
            .build()
            .load_key(infra_root_keypair.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();
    let infra_root_certbundle =
        CertificateBundle::<Infrastructure>::new(infra_root_cert.clone(), None);

    // make a keyserver intermediate cert
    let keyserver_inter_keypair = KeyPair::new_random();
    let keyserver_inter_cert_req = RequestBuilder::<Infrastructure>::intermediate_v1_builder(
        keyserver_inter_keypair.public_key(),
    )
    .build();
    let keyserver_inter_cert_bundle = infra_root_certbundle
        .issue_cert_bundle(
            keyserver_inter_cert_req,
            IssuerAdditionalFields {
                expiration: Expiration::expiring_in_days(60).unwrap(),
                emails_to_notify: vec![],
            },
            infra_root_keypair.clone(),
        )
        .unwrap();

    // make a keyserver leaf cert
    let infra_leaf_keypair = KeyPair::new_random();
    let infra_leaf_cert_req =
        RequestBuilder::<Infrastructure>::leaf_v1_builder(infra_leaf_keypair.public_key()).build();
    let infra_leaf_cert_bundle = keyserver_inter_cert_bundle
        .issue_cert_bundle(
            infra_leaf_cert_req,
            IssuerAdditionalFields {
                expiration: Expiration::expiring_in_days(60).unwrap(),
                emails_to_notify: vec![],
            },
            keyserver_inter_keypair,
        )
        .unwrap();

    // make keyserver token
    let keyserver_keypair = KeyPair::new_random();
    let keyserver_req =
        KeyserverTokenRequest::v1_token_request(keyserver_keypair.public_key(), keyserver_id);
    let keyserver_tokenbundle = infra_leaf_cert_bundle
        .issue_keyserver_token_bundle(
            keyserver_req,
            Expiration::expiring_in_days(60).unwrap(),
            infra_leaf_keypair.clone(),
        )
        .unwrap();

    // make database token
    let database_keypair = KeyPair::new_random();
    let database_req = DatabaseTokenRequest::v1_token_request(database_keypair.public_key());
    let database_tokenbundle = infra_leaf_cert_bundle
        .issue_database_token_bundle(
            database_req,
            Expiration::expiring_in_days(60).unwrap(),
            infra_leaf_keypair.clone(),
        )
        .unwrap();

    // make manufacturer root
    let manu_root_keypair = KeyPair::new_random();
    let manu_root_cert =
        RequestBuilder::<Manufacturer>::root_v1_builder(manu_root_keypair.public_key())
            .build()
            .load_key(manu_root_keypair.clone())
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap()
            .into_key_unavailable();
    let manu_root_certbundle = CertificateBundle::<Manufacturer>::new(manu_root_cert.clone(), None);

    // make manufacturer intermediate
    let manu_inter_keypair = KeyPair::new_random();
    let manu_inter_cert_req =
        RequestBuilder::<Manufacturer>::intermediate_v1_builder(manu_inter_keypair.public_key())
            .build();
    let manu_inter_cert_bundle = manu_root_certbundle
        .issue_cert_bundle(
            manu_inter_cert_req,
            IssuerAdditionalFields {
                expiration: Expiration::expiring_in_days(60).unwrap(),
                emails_to_notify: vec![],
            },
            manu_root_keypair.clone(),
        )
        .unwrap();

    // make manufacturer leaf
    let manu_leaf_keypair = KeyPair::new_random();
    let manu_leaf_cert_req =
        RequestBuilder::<Manufacturer>::leaf_v1_builder(manu_leaf_keypair.public_key()).build();
    let manu_leaf_cert_bundle = manu_inter_cert_bundle
        .issue_cert_bundle(
            manu_leaf_cert_req,
            IssuerAdditionalFields {
                expiration: Expiration::expiring_in_days(60).unwrap(),
                emails_to_notify: vec![],
            },
            manu_inter_keypair,
        )
        .unwrap();

    // make synthesizer token
    let synth_keypair = KeyPair::new_random();
    let synth_req = SynthesizerTokenRequest::v1_token_request(
        synth_keypair.public_key(),
        "example.com",
        "synthesizer mcsynthface",
        "1337",
        1_000,
        None,
    );
    let synth_tokenbundle = manu_leaf_cert_bundle
        .issue_synthesizer_token_bundle(
            synth_req,
            Expiration::expiring_in_days(60).unwrap(),
            manu_leaf_keypair.clone(),
        )
        .unwrap();

    CreatedCerts {
        infra_root_keypair: infra_root_keypair.clone(),
        infra_root_cert: infra_root_cert
            .load_key(infra_root_keypair.clone())
            .unwrap(),
        infra_root_certbundle,
        keyserver_keypair,
        keyserver_tokenbundle,
        database_keypair,
        database_tokenbundle,
        manu_root_keypair: manu_root_keypair.clone(),
        manu_root_cert: manu_root_cert.load_key(manu_root_keypair).unwrap(),
        manu_root_certbundle,
        synth_keypair,
        synth_tokenbundle,
    }
}
