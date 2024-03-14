// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structs used to define the type of a `Certificate`

use std::{fmt::Display, str::FromStr};

use rasn::{types::*, Decode, Encode};
use serde::Serialize;
use thiserror::Error;

use crate::{
    asn::AsnCompatible,
    shared_components::common::{ComponentVersionGuard, VersionedComponent},
};

/// This trait represents the level of a certificate in the issuing hierarchy.
pub trait HierarchyLevel: Clone + PartialEq + Eq + AsnCompatible {}

/// Represents the topmost level of the hierarchy.
pub trait Root: HierarchyLevel {}

/// Represents the middle level of the hierarchy.
pub trait Intermediate: HierarchyLevel {}

/// Represents the lowest level of the hierarchy. A leaf certificate is unable to issue other certificates.
pub trait Leaf: HierarchyLevel {}

#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct Root1 {
    guard: ComponentVersionGuard<Self>,
}

impl Root1 {
    pub fn new() -> Root1 {
        let guard = ComponentVersionGuard::new();
        Self { guard }
    }
}

impl VersionedComponent for Root1 {
    const COMPONENT_NAME: &'static str = "ROOT";
    const ITERATION: u16 = 1;
}

impl Default for Root1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Root for Root1 {}
impl HierarchyLevel for Root1 {}

#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct Intermediate1 {
    guard: ComponentVersionGuard<Self>,
}

impl Intermediate1 {
    pub fn new() -> Intermediate1 {
        let guard = ComponentVersionGuard::new();
        Self { guard }
    }
}

impl VersionedComponent for Intermediate1 {
    const COMPONENT_NAME: &'static str = "INT";
    const ITERATION: u16 = 1;
}

impl Default for Intermediate1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Intermediate for Intermediate1 {}
impl HierarchyLevel for Intermediate1 {}

#[derive(
    AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize,
)]
#[rasn(automatic_tags)]
pub struct Leaf1 {
    guard: ComponentVersionGuard<Self>,
}

impl Leaf1 {
    pub fn new() -> Leaf1 {
        let guard = ComponentVersionGuard::new();
        Self { guard }
    }
}

impl VersionedComponent for Leaf1 {
    const COMPONENT_NAME: &'static str = "LEAF";
    const ITERATION: u16 = 1;
}

impl Default for Leaf1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Leaf for Leaf1 {}
impl HierarchyLevel for Leaf1 {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HierarchyKind {
    Root,
    Intermediate,
    Leaf,
}

impl HierarchyKind {
    pub fn short_name(&self) -> &str {
        match self {
            HierarchyKind::Root => "root",
            HierarchyKind::Intermediate => "int",
            HierarchyKind::Leaf => "leaf",
        }
    }
}

impl Display for HierarchyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HierarchyKind::Root => write!(f, "root"),
            HierarchyKind::Intermediate => write!(f, "intermediate"),
            HierarchyKind::Leaf => write!(f, "leaf"),
        }
    }
}

#[derive(Error, Debug)]
#[error("could not parse cert hierarchy, expected one of (root, intermediate, leaf)")]
pub struct HierarchyKindParseError;
impl FromStr for HierarchyKind {
    type Err = HierarchyKindParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" => Ok(HierarchyKind::Root),
            "int" | "intermediate" => Ok(HierarchyKind::Intermediate),
            "leaf" => Ok(HierarchyKind::Leaf),
            _ => Err(HierarchyKindParseError),
        }
    }
}

/// Example for updated Leaf certificate version
// #[derive(AsnType, Decode, Encode, Debug, Clone, PartialEq, Eq)]
// #[rasn(automatic_tags)]
// pub struct Leaf2 {
//     guard: ComponentVersionGuard<Self>,
//     pub additional_field: usize,
// }

// impl Leaf2 {
//     pub fn new(additional_field: usize) -> Leaf2 {
//         let guard = VersionGuard::new();
//         Self { guard, additional_field }
//     }
// }
// impl Versioned for Leaf2 {
//     const COMPONENT_NAME: &'static str = "LEAF";
//     const ITERATION: u16 = 2;
// }
// impl Leaf for Leaf2 {}
// impl HierarchyLevel for Leaf2 {}

#[cfg(test)]
mod test {
    use crate::asn::{FromASN1DerBytes, ToASN1DerBytes};

    use super::{Leaf1, Root1};

    #[test]
    fn asn_encoding_distinguishes_between_hierarchy_types() {
        let leaf = Leaf1::new();
        let encoded_leaf = leaf.to_der().unwrap();
        assert!(Root1::from_der(encoded_leaf).is_err());
    }
}
