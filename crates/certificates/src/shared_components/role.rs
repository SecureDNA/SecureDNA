// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt::Debug;
use std::hash::Hash;
use std::{marker::PhantomData, str::FromStr};

use rasn::{de::Error, types::Utf8String, AsnType, Decode, Encode, Tag};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::asn::AsnCompatible;
use crate::certificate::{
    CertificateVersion, ExemptionCertificateVersion, ExemptionRequestVersion,
    InfrastructureCertificateVersion, InfrastructureRequestVersion, ManufacturerCertificateVersion,
    ManufacturerRequestVersion, RequestVersion,
};

/// This trait represents the role or 'family type' of a certificate.
/// Certificates are only able to issue other certificates that have an identical role.
/// The type of token that can  be issued by a certificate is also constrained by its role.
/// For example, only certificates with the `Exemption` role can issue `Exemption Tokens`.
pub trait Role:
    Debug + Clone + PartialEq + Eq + Hash + PartialOrd + Ord + AsnCompatible + Serialize + Default
{
    const DESCRIPTION: &'static str;

    /// A role-specific enum which allows different certificates to have different fields
    type CertVersion: CertificateVersion<ReqVersion = Self::ReqVersion>;
    /// A role-specific enum which allows different certificate requests to have different fields
    type ReqVersion: RequestVersion<CertVersion = Self::CertVersion>;
}

// `RoleGuard` ensures that serialized or encoded certificates cannot be
// deserialized or decoded as a certificate with a different role.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleGuard<R>(pub PhantomData<R>)
where
    R: Role;

impl<R: Role> Serialize for RoleGuard<R> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(R::DESCRIPTION)
    }
}

impl<'de, R: Role> Deserialize<'de> for RoleGuard<R> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;
        if name == R::DESCRIPTION {
            Ok(RoleGuard(PhantomData))
        } else {
            Err(serde::de::Error::custom(format!(
                "unexpected role type: {}, expected {}",
                name,
                R::DESCRIPTION.to_lowercase()
            )))
        }
    }
}

impl<R: Role> AsnType for RoleGuard<R> {
    const TAG: rasn::Tag = Tag::UTF8_STRING;
}
impl<R: Role> Encode for RoleGuard<R> {
    fn encode_with_tag_and_constraints<E: rasn::Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: rasn::types::Constraints,
    ) -> Result<(), E::Error> {
        R::DESCRIPTION.encode_with_tag_and_constraints(encoder, tag, constraints)
    }
}

impl<R: Role> Decode for RoleGuard<R> {
    fn decode_with_tag_and_constraints<D: rasn::Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: rasn::types::Constraints,
    ) -> Result<Self, D::Error> {
        let name = Utf8String::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        if name == R::DESCRIPTION {
            Ok(RoleGuard(PhantomData))
        } else {
            Err(D::Error::custom(format!(
                "unexpected role type: {}, expected {}",
                name,
                R::DESCRIPTION.to_lowercase()
            )))
        }
    }
}

/// The role held by the chain of certificates responsible for issuing exemption tokens.
#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Default,
)]
#[rasn(automatic_tags)]
pub struct Exemption;
impl Role for Exemption {
    const DESCRIPTION: &'static str = "EXEMPTION";
    type CertVersion = ExemptionCertificateVersion;
    type ReqVersion = ExemptionRequestVersion;
}

/// The role held by the chain of certificates responsible for issuing tokens for use within the SecureDNA infrastructure.
#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Default,
)]
#[rasn(automatic_tags)]
pub struct Infrastructure;
impl Role for Infrastructure {
    const DESCRIPTION: &'static str = "INFRASTRUCTURE";
    type CertVersion = InfrastructureCertificateVersion;
    type ReqVersion = InfrastructureRequestVersion;
}

/// The role held by the chain of certificates responsible for issuing tokens to identify synthesizer machines.
#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Default,
)]
#[rasn(automatic_tags)]
pub struct Manufacturer;
impl Role for Manufacturer {
    const DESCRIPTION: &'static str = "MANUFACTURER";
    type CertVersion = ManufacturerCertificateVersion;
    type ReqVersion = ManufacturerRequestVersion;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoleKind {
    Exemption,
    Infrastructure,
    Manufacturer,
}

#[derive(Error, Debug)]
#[error("could not parse cert role, expected one of (exemption, infrastructure, manufacturer)")]
pub struct RoleKindParseError;
impl FromStr for RoleKind {
    type Err = RoleKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exemption" => Ok(RoleKind::Exemption),
            "infrastructure" | "infra" => Ok(RoleKind::Infrastructure),
            "manufacturer" => Ok(RoleKind::Manufacturer),
            _ => Err(RoleKindParseError),
        }
    }
}
