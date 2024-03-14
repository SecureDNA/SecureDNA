// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pem::{encode_config, parse, EncodeConfig, LineEnding, Pem};

use crate::{
    asn::{FromASN1DerBytes, ToASN1DerBytes},
    error::{DecodeError, EncodeError},
};

pub trait PemEncodable: ToASN1DerBytes + PemTaggable {
    /// Converts to PEM string.
    fn to_pem(&self) -> Result<String, EncodeError>;
}

pub trait PemDecodable: FromASN1DerBytes + Sized + PemTaggable {
    fn from_pem<T: AsRef<[u8]>>(data: T) -> Result<Self, DecodeError>;
}

pub trait PemTaggable {
    fn tag() -> String;
}

impl<T: ToASN1DerBytes + PemTaggable> PemEncodable for T {
    fn to_pem(&self) -> Result<String, EncodeError> {
        let pem = to_pem_inner(self)?;
        let config = EncodeConfig::new().set_line_ending(LineEnding::LF);
        let s = encode_config(&pem, config);
        Ok(s)
    }
}

fn to_pem_inner<T: ToASN1DerBytes + PemTaggable>(item: &T) -> Result<Pem, EncodeError> {
    let contents = item.to_der()?;
    Ok(Pem::new(T::tag(), contents))
}

fn from_pem_inner<T: FromASN1DerBytes + PemTaggable>(pem: &Pem) -> Result<T, DecodeError> {
    if pem.tag() != T::tag() {
        return Err(DecodeError::UnexpectedPEMTag(
            T::tag(),
            pem.tag().to_owned(),
        ));
    }
    T::from_der(pem.contents())
}

impl<T: FromASN1DerBytes + PemTaggable> PemDecodable for T {
    fn from_pem<K: AsRef<[u8]>>(data: K) -> Result<Self, DecodeError> {
        let pem = parse(data)?;
        from_pem_inner::<T>(&pem)
    }
}

pub struct MultiItemPemBuilder(Vec<Pem>);

impl MultiItemPemBuilder {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn add_item<T: PemEncodable>(&mut self, item: &T) -> Result<(), EncodeError> {
        let pem = to_pem_inner(item)?;
        self.0.push(pem);
        Ok(())
    }

    pub fn finish(self) -> String {
        let config = EncodeConfig::new().set_line_ending(LineEnding::LF);
        pem::encode_many_config(&self.0, config)
    }

    pub fn parse<B: AsRef<[u8]>>(data: B) -> Result<Self, DecodeError> {
        let items = pem::parse_many(data)?;
        Ok(Self(items))
    }

    /// Finds all PEM encoded items of type `T`. If none found it will return an empty `Vec`. If any items with the matching tag fail
    /// decoding then an error will be returned.
    pub fn find_all<T: PemDecodable>(&self) -> Result<Vec<T>, DecodeError> {
        self.0
            .iter()
            .filter(|x| x.tag() == T::tag())
            .map(|p| from_pem_inner::<T>(p))
            .collect::<Result<Vec<_>, _>>()
    }
}

impl Default for MultiItemPemBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct MultiPemError;
