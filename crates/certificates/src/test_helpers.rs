// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use doprf::party::KeyserverId;
use time::{format_description::well_known::Rfc2822, OffsetDateTime};

use crate::key_traits::HasAssociatedKey;
use crate::{
    asn::{FromASN1DerBytes, ToASN1DerBytes},
    Authenticator, Builder, Certificate, CertificateBundle, CertificateRequest, DatabaseToken,
    DatabaseTokenGroup, DatabaseTokenRequest, Description, Exemption, ExemptionToken,
    ExemptionTokenGroup, ExemptionTokenRequest, Expiration, GenbankId, HltToken, HltTokenGroup,
    HltTokenRequest, IssuanceError, Issued, IssuerAdditionalFields, KeyAvailable, KeyPair,
    KeyUnavailable, KeyserverToken, KeyserverTokenGroup, KeyserverTokenRequest, Organism,
    PublicKey, RequestBuilder, Role, Sequence, SequenceIdentifier, SynthesizerToken,
    SynthesizerTokenGroup, SynthesizerTokenRequest, TokenBundle, TokenGroup, YubikeyId,
};

pub fn create_leaf_cert<R: Role>() -> Certificate<R, KeyAvailable>
where
    RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
{
    let kp = KeyPair::new_random();
    let root_cert = RequestBuilder::<R>::root_v1_builder(kp.public_key())
        .build()
        .load_key(kp)
        .unwrap()
        .self_sign(IssuerAdditionalFields::default())
        .unwrap();

    let int_kp = KeyPair::new_random();
    let int_req = RequestBuilder::<R>::intermediate_v1_builder(int_kp.public_key()).build();

    let intermediate_cert = root_cert
        .issue_cert(int_req, IssuerAdditionalFields::default())
        .expect("Couldn't issue cert")
        .load_key(int_kp)
        .unwrap();

    let leaf_kp = KeyPair::new_random();
    let leaf_req = RequestBuilder::<R>::leaf_v1_builder(leaf_kp.public_key()).build();

    intermediate_cert
        .issue_cert(leaf_req, IssuerAdditionalFields::default())
        .expect("Could not sign leaf cert")
        .load_key(leaf_kp)
        .unwrap()
}

pub fn create_intermediate_bundle<R: Role>() -> (CertificateBundle<R>, KeyPair, PublicKey)
where
    RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
{
    let kp = KeyPair::new_random();
    let root_pk = kp.public_key();
    let root_cert = RequestBuilder::<R>::root_v1_builder(kp.public_key())
        .build()
        .load_key(kp)
        .unwrap()
        .self_sign(IssuerAdditionalFields::default())
        .unwrap();

    let int_kp = KeyPair::new_random();
    let int_req = RequestBuilder::<R>::intermediate_v1_builder(int_kp.public_key()).build();

    let intermediate_cert = root_cert
        .issue_cert(int_req, IssuerAdditionalFields::default())
        .expect("Couldn't issue cert");

    (
        CertificateBundle::new(intermediate_cert, None),
        int_kp,
        root_pk,
    )
}

pub fn create_cross_signed_intermediate_bundle<R: Role>(
) -> (CertificateBundle<R>, KeyPair, PublicKey)
where
    RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
{
    let kp = KeyPair::new_random();
    let root_pk = kp.public_key();
    let root_cert = RequestBuilder::<R>::root_v1_builder(kp.public_key())
        .build()
        .load_key(kp)
        .unwrap()
        .self_sign(IssuerAdditionalFields::default())
        .unwrap();

    let int_kp = KeyPair::new_random();
    let int_req_a = RequestBuilder::<R>::intermediate_v1_builder(int_kp.public_key()).build();
    let int_req_b = int_req_a.clone();

    let int_cert_a = root_cert
        .issue_cert(int_req_a, IssuerAdditionalFields::default())
        .expect("Couldn't issue cert");

    let int_cert_b = root_cert
        .issue_cert(int_req_b, IssuerAdditionalFields::default())
        .expect("Couldn't issue cert");

    let bundle = CertificateBundle::new(int_cert_a, None)
        .merge(CertificateBundle::new(int_cert_b, None))
        .unwrap();

    (bundle, int_kp, root_pk)
}

pub fn create_leaf_bundle<R: Role>() -> (CertificateBundle<R>, KeyPair, PublicKey)
where
    RequestBuilder<R>: Builder<Item = CertificateRequest<R, KeyUnavailable>>,
{
    let kp = KeyPair::new_random();
    let root_pk = kp.public_key();
    let root_cert = RequestBuilder::<R>::root_v1_builder(kp.public_key())
        .build()
        .load_key(kp)
        .unwrap()
        .self_sign(IssuerAdditionalFields::default())
        .unwrap();

    let int_kp = KeyPair::new_random();
    let int_req = RequestBuilder::<R>::intermediate_v1_builder(int_kp.public_key()).build();

    let intermediate_cert = root_cert
        .issue_cert(int_req, IssuerAdditionalFields::default())
        .expect("Couldn't issue cert")
        .load_key(int_kp)
        .unwrap();

    let leaf_kp = KeyPair::new_random();
    let leaf_req = RequestBuilder::<R>::leaf_v1_builder(leaf_kp.public_key()).build();

    let leaf_cert = intermediate_cert
        .issue_cert(leaf_req, IssuerAdditionalFields::default())
        .expect("Could not sign leaf cert");

    let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);
    let chain = int_cert_bundle.issue_chain();

    (
        CertificateBundle::new(leaf_cert, Some(chain)),
        leaf_kp,
        root_pk,
    )
}

pub fn create_etr_with_options(
    public_key: Option<PublicKey>,
    exemptions: Vec<Organism>,
    auth_devices: Vec<Authenticator>,
) -> ExemptionTokenRequest {
    let requestor = Description::default()
        .with_name("some researcher")
        .with_email("email@example.com");

    let shipping_address = vec!["19 Some Street".to_string(), "Some City".to_string()];

    ExemptionTokenRequest::v1_token_request(
        public_key,
        exemptions,
        requestor,
        auth_devices,
        vec![shipping_address],
    )
}

pub fn create_etr(exemptions: Vec<Organism>) -> ExemptionTokenRequest {
    let auth_device = Authenticator::Yubikey(YubikeyId::try_new("cccjgjgkhcbb").unwrap());
    create_etr_with_options(None, exemptions, vec![auth_device])
}

pub fn create_et_with_auth_devices(
    exemptions: Vec<Organism>,
    requestor_auth_devices: Vec<Authenticator>,
    issuer_auth_devices: Vec<Authenticator>,
) -> ExemptionToken<KeyUnavailable> {
    let leaf_cert = create_leaf_cert::<Exemption>();
    let etr = create_etr_with_options(None, exemptions, requestor_auth_devices);

    leaf_cert
        .issue_exemption_token(
            etr,
            Expiration::expiring_in_days(90).unwrap(),
            issuer_auth_devices,
        )
        .unwrap()
}

pub fn create_synth_token_request() -> (SynthesizerTokenRequest, KeyPair) {
    let kp = KeyPair::new_random();

    let token = SynthesizerTokenRequest::v1_token_request(
        kp.public_key(),
        "maker.synth",
        "XL",
        "10AK",
        10_000u64,
        None,
    );
    (token, kp)
}

fn create_token_bundle<T, F, G>(create_req_fn: F, issue_token_fn: G) -> (TokenBundle<T>, PublicKey)
where
    T: TokenGroup,
    F: FnOnce() -> T::TokenRequest,
    G: FnOnce(
        Certificate<T::AssociatedRole, KeyAvailable>,
        T::TokenRequest,
    ) -> Result<T::Token, IssuanceError>,
    RequestBuilder<T::AssociatedRole>:
        Builder<Item = CertificateRequest<T::AssociatedRole, KeyUnavailable>>,
{
    let (leaf_bundle, leaf_kp, root_public_key) = create_leaf_bundle::<T::AssociatedRole>();

    let issuing_cert = leaf_bundle
        .get_lead_cert()
        .unwrap()
        .to_owned()
        .load_key(leaf_kp)
        .unwrap();

    let request = create_req_fn();
    let token = issue_token_fn(issuing_cert, request).unwrap();

    let chain = leaf_bundle.issue_chain();
    let token_bundle = TokenBundle::<T>::new(token, chain);
    (token_bundle, root_public_key)
}

pub fn create_issuing_exemption_token_bundle(
) -> (TokenBundle<ExemptionTokenGroup>, KeyPair, PublicKey) {
    let keypair = KeyPair::new_random();
    let create_etr = || create_etr_with_options(Some(keypair.public_key()), vec![], vec![]);
    let (bundle, root_public_key) = create_token_bundle(create_etr, |cert, req| {
        cert.issue_exemption_token(req, Expiration::default(), vec![])
    });
    (bundle, keypair, root_public_key)
}

pub fn create_et_bundle_with_exemptions(
    exemptions: Vec<Organism>,
) -> (TokenBundle<ExemptionTokenGroup>, PublicKey) {
    create_token_bundle(
        || create_etr(exemptions),
        |cert, req| cert.issue_exemption_token(req, Expiration::default(), vec![]),
    )
}

pub fn create_et_bundle_from_leaf_bundle(
    exemptions: Vec<Organism>,
    leaf_bundle: &CertificateBundle<Exemption>,
    leaf_kp: KeyPair,
) -> TokenBundle<ExemptionTokenGroup> {
    let request = create_etr(exemptions);
    leaf_bundle
        .issue_exemption_token_bundle(request, Expiration::default(), vec![], leaf_kp)
        .unwrap()
}

pub fn create_exemptions() -> Vec<Organism> {
    vec![Organism::new(
        "Chlamydia psittaci",
        vec![
            SequenceIdentifier::Id(GenbankId::try_new("1112252").unwrap()),
            SequenceIdentifier::Id(GenbankId::try_new("1112253").unwrap()),
            SequenceIdentifier::Dna(
                Sequence::try_new(
                    ">Virus1\nAC\nT\n>Empty\n\n>Virus2\n>with many\n>comment lines\nC  AT",
                )
                .unwrap(),
            ),
        ],
    )]
}

pub fn create_exemption_token_bundle() -> (TokenBundle<ExemptionTokenGroup>, PublicKey) {
    create_et_bundle_with_exemptions(create_exemptions())
}

pub fn create_child_exemption_token_bundle() -> (TokenBundle<ExemptionTokenGroup>, PublicKey) {
    let (et_bundle, et_kp, root) = create_issuing_exemption_token_bundle();
    let child_etr = create_etr_with_options(None, vec![], vec![]);
    let child_et = et_bundle
        .token
        .clone()
        .load_key(et_kp)
        .unwrap()
        .issue_exemption_token(child_etr, Expiration::default(), vec![])
        .unwrap();
    let token_bundle = TokenBundle::<ExemptionTokenGroup>::new(child_et, et_bundle.issue_chain());
    (token_bundle, root)
}

pub fn create_database_token_bundle() -> (TokenBundle<DatabaseTokenGroup>, PublicKey) {
    create_token_bundle(
        || {
            let kp = KeyPair::new_random();
            DatabaseTokenRequest::v1_token_request(kp.public_key())
        },
        |cert, req| cert.issue_database_token(req, Expiration::default()),
    )
}

pub fn create_hlt_token_bundle() -> (TokenBundle<HltTokenGroup>, PublicKey) {
    create_token_bundle(
        || {
            let kp = KeyPair::new_random();
            HltTokenRequest::v1_token_request(kp.public_key())
        },
        |cert, req| cert.issue_hlt_token(req, Expiration::default()),
    )
}

pub fn create_keyserver_token_bundle() -> (TokenBundle<KeyserverTokenGroup>, PublicKey) {
    create_token_bundle(
        || {
            let kp = KeyPair::new_random();
            KeyserverTokenRequest::v1_token_request(
                kp.public_key(),
                KeyserverId::try_from(1).unwrap(),
            )
        },
        |cert, req| cert.issue_keyserver_token(req, Expiration::default()),
    )
}

pub fn create_synthesizer_token_bundle() -> (TokenBundle<SynthesizerTokenGroup>, PublicKey) {
    create_token_bundle(
        || {
            let (token, _) = create_synth_token_request();
            token
        },
        |cert, req| cert.issue_synthesizer_token(req, Expiration::default()),
    )
}

#[cfg(test)]
#[macro_export]
macro_rules! test_for_all_token_types {
    ($test_fn:ident) => {
        $crate::test_for_token_types!(
            child_exemption, exemption, database, hlt, keyserver, synthesizer;
            $test_fn
        );
    };
}

#[cfg(test)]
#[macro_export]
macro_rules! test_for_token_types {
    ($($token_type:ident),*; $test_fn:ident) => {
        paste::item! {
            $(
                #[test]
                fn [< $test_fn _for_ $token_type _token_bundle >]() {
                    $test_fn($crate::test_helpers::[<create_ $token_type _token_bundle>]);
                }
            )*
        }
    };
}

/// Concatenate the arguments with a newline. No newline is added at the end.
#[macro_export]
macro_rules! concat_with_newline {
    ($line:expr) => {
        $line
    };
    ($first:expr, $($rest:expr),+ $(,)?) => {
        concat!($first, "\n", concat_with_newline!($($rest),+))
    };
}

pub fn expected_cert_display<R: Role, K>(
    cert: &Certificate<R, K>,
    expected_hierarchy_level: &str,
    expected_role: &str,
    expected_issued_to: &str,
    expected_issued_by: &str,
    expected_email_section: Option<&str>,
) -> String {
    let issuance_id = cert.issuance_id().to_string();
    let request_id = cert.request_id().to_string();
    let issued_on = OffsetDateTime::from_unix_timestamp(cert.expiration().not_valid_before)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let expires_on = OffsetDateTime::from_unix_timestamp(cert.expiration().not_valid_after)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let signature = cert.signature().to_string();

    let mut text = format!(
        concat_with_newline!(
            "{} V1 {} Certificate",
            "  Issuance ID:",
            "    {}",
            "  Request ID:",
            "    {}",
            "  Issued to:",
            "    {}",
            "  Issued by:",
            "    {}",
            "  Issued on:",
            "    {}",
            "  Expires:",
            "    {}",
            "  Signature:",
            "    {}"
        ),
        expected_hierarchy_level,
        expected_role,
        &issuance_id,
        &request_id,
        expected_issued_to,
        expected_issued_by,
        &issued_on,
        &expires_on,
        &signature,
    );
    if let Some(email_section) = expected_email_section {
        text.push_str(&format!("\n{}", email_section));
    }
    text
}

pub fn expected_cert_request_display<R: Role, K>(
    req: &CertificateRequest<R, K>,
    expected_hierarchy_level: &str,
    expected_role: &str,
    expected_subject: &str,
    expected_email_section: Option<&str>,
) -> String {
    let request_id = req.request_id().to_string();

    let mut text = format!(
        concat_with_newline!(
            "{} V1 {} Certificate Request",
            "  Request ID:",
            "    {}",
            "  Subject:",
            "    {}",
        ),
        expected_hierarchy_level, expected_role, request_id, expected_subject,
    );
    if let Some(email_section) = expected_email_section {
        text.push_str(&format!("\n{}", email_section));
    }
    text
}

pub fn expected_database_token_display<K>(token: &DatabaseToken<K>, issued_by: &str) -> String {
    let issued_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_before)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let expires_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_after)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();

    format!(
        concat_with_newline!(
            "V1 Database Token",
            "  Issuance ID:",
            "    {}",
            "  Request ID:",
            "    {}",
            "  Public Key:",
            "    {}",
            "  Issued by:",
            "    {}",
            "  Issued on:",
            "    {}",
            "  Expires:",
            "    {}",
            "  Signature:",
            "    {}",
        ),
        token.issuance_id(),
        token.request_id(),
        token.public_key(),
        issued_by,
        issued_on,
        expires_on,
        token.signature()
    )
}

pub fn expected_hlt_token_display<K>(token: &HltToken<K>, issued_by: &str) -> String {
    let issued_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_before)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let expires_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_after)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();

    format!(
        concat_with_newline!(
            "V1 HLT Token",
            "  Issuance ID:",
            "    {}",
            "  Request ID:",
            "    {}",
            "  Public Key:",
            "    {}",
            "  Issued by:",
            "    {}",
            "  Issued on:",
            "    {}",
            "  Expires:",
            "    {}",
            "  Signature:",
            "    {}",
        ),
        token.issuance_id(),
        token.request_id(),
        token.public_key(),
        issued_by,
        issued_on,
        expires_on,
        token.signature()
    )
}

pub fn expected_keyserver_token_display<K>(
    token: &KeyserverToken<K>,
    keyserver_id: &str,
    issued_by: &str,
) -> String {
    let issued_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_before)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let expires_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_after)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();

    format!(
        concat_with_newline!(
            "V1 Keyserver Token",
            "  Issuance ID:",
            "    {}",
            "  Request ID:",
            "    {}",
            "  Public Key:",
            "    {}",
            "  Keyserver ID:",
            "    {}",
            "  Issued by:",
            "    {}",
            "  Issued on:",
            "    {}",
            "  Expires:",
            "    {}",
            "  Signature:",
            "    {}",
        ),
        token.issuance_id(),
        token.request_id(),
        token.public_key(),
        keyserver_id,
        issued_by,
        issued_on,
        expires_on,
        token.signature()
    )
}

pub fn expected_synthesizer_token_display<K>(
    token: &SynthesizerToken<K>,
    domain: &str,
    model: &str,
    serial: &str,
    max_dna_base_pairs_per_day: &str,
    audit_section: Option<&str>,
    issued_by: &str,
) -> String {
    let issued_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_before)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();
    let expires_on = OffsetDateTime::from_unix_timestamp(token.expiration().not_valid_after)
        .unwrap()
        .format(&Rfc2822)
        .unwrap();

    let mut text = format!(
        concat_with_newline!(
            "V1 Synthesizer Token",
            "  Issuance ID:",
            "    {}",
            "  Request ID:",
            "    {}",
            "  Public Key:",
            "    {}",
            "  Manufacturer Domain:",
            "    {}",
            "  Model:",
            "    {}",
            "  Serial Number:",
            "    {}",
            "  Rate Limit:",
            "    {}",
        ),
        token.issuance_id(),
        token.request_id(),
        token.public_key(),
        domain,
        model,
        serial,
        max_dna_base_pairs_per_day,
    );
    if let Some(audit_section) = audit_section {
        text.push_str(&format!(
            concat_with_newline!("\n  Audit Recipient:", "    {}",),
            audit_section,
        ));
    }
    text.push_str(&format!(
        concat_with_newline!(
            "\n  Issued by:",
            "    {}",
            "  Issued on:",
            "    {}",
            "  Expires:",
            "    {}",
            "  Signature:",
            "    {}",
        ),
        issued_by,
        issued_on,
        expires_on,
        token.signature(),
    ));
    text
}

/// For use in testing behaviour when signature fails verification
pub trait BreakableSignature: Issued + FromASN1DerBytes + ToASN1DerBytes {
    fn break_signature(&mut self) {
        let sig = self.signature().as_ref();
        let mut data = self.to_der().unwrap();

        if let Some(position) = data.windows(sig.len()).position(|window| window == sig) {
            data[position] = data[position].wrapping_add(1);
        } else {
            panic!("signature not broken")
        }

        *self = Self::from_der(data).unwrap();
    }
}

impl<T: Issued + FromASN1DerBytes + ToASN1DerBytes> BreakableSignature for T {}
