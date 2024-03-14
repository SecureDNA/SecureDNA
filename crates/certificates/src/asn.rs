// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use rasn::{der, types::AsnType, Decode, Encode};

use crate::error::{DecodeError, EncodeError};

pub trait AsnCompatible: AsnType + Encode + Decode {}
impl<T: AsnType + Encode + Decode> AsnCompatible for T {}

pub trait ToASN1DerBytes {
    /// Converts to an ASN.1 DER-encoded byte vector.
    fn to_der(&self) -> Result<Vec<u8>, EncodeError>;
}

pub trait FromASN1DerBytes: Sized {
    /// Converts from an ASN.1 DER-encoded byte vector.
    fn from_der<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError>;
}

impl<T: AsnType + Encode + Sized> ToASN1DerBytes for T {
    fn to_der(&self) -> Result<Vec<u8>, EncodeError> {
        der::encode(self).map_err(|err| EncodeError::AsnEncode(err.to_string()))
    }
}

impl<T: AsnType + Decode> FromASN1DerBytes for T {
    fn from_der<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError> {
        der::decode::<Self>(data.as_ref()).map_err(|err| DecodeError::AsnDecode(err.to_string()))
    }
}

///  Macro to generate implementations of the `AsnType`, `Encode`, and `Decode` traits for a tuple struct with a single fixed-size array field.
// This is to replace rasn's default implementation which encodes each byte as a separate integer.
#[macro_export]
macro_rules! asn_encode_as_octet_string_impl {
    ($t:ident, $len:expr) => {
        impl rasn::AsnType for $t {
            const TAG: rasn::Tag = rasn::Tag::OCTET_STRING;
        }

        impl rasn::Encode for $t {
            fn encode_with_tag_and_constraints<E: rasn::Encoder>(
                &self,
                encoder: &mut E,
                tag: rasn::Tag,
                constraints: rasn::prelude::Constraints,
            ) -> Result<(), E::Error> {
                encoder
                    .encode_octet_string(tag, constraints, &self.0)
                    .map(drop)
            }
        }

        impl rasn::Decode for $t {
            fn decode_with_tag_and_constraints<D: rasn::Decoder>(
                decoder: &mut D,
                tag: rasn::Tag,
                constraints: rasn::prelude::Constraints,
            ) -> Result<Self, D::Error> {
                let inner: [u8; Self::LEN] =
                    rasn::prelude::OctetString::decode_with_tag_and_constraints(
                        decoder,
                        tag,
                        constraints,
                    )?
                    .as_ref()
                    .try_into()
                    .map_err(|_| {
                        rasn::de::Error::custom(format!("Invalid encoding for {}", stringify!($t)))
                    })?;

                Ok(Self(inner))
            }
        }
    };
}
