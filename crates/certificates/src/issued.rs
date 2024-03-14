// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::validation_failure::{InvalidityReason, ValidationFailure};
use crate::{
    certificate::Certificate,
    error::EncodeError,
    keypair::{PublicKey, Signature},
    shared_components::{
        common::{Expiration, Id},
        role::Role,
    },
};

// For use in cert traversal
pub trait Issued {
    fn request_id(&self) -> &Id;
    fn issuance_id(&self) -> &Id;
    fn issuer_public_key(&self) -> &PublicKey;
    fn issuer_description(&self) -> &str;
    fn signature(&self) -> &Signature;
    fn expiration(&self) -> &Expiration;
    fn data(&self) -> Result<Vec<u8>, EncodeError>;

    fn was_issued_by_cert<R: Role, K>(&self, cert: &Certificate<R, K>) -> bool {
        self.issuer_public_key() == cert.public_key()
    }

    fn was_issued_by_public_key(&self, pk: &PublicKey) -> bool {
        self.issuer_public_key() == pk
    }

    fn validate(&self) -> Result<(), ValidationFailure> {
        let mut validation_failures = vec![];
        if let Err(details) = self.expiration().validate() {
            validation_failures.push(InvalidityReason::ValidityPeriod(details))
        };
        if !self.signature_verifies() {
            validation_failures.push(InvalidityReason::SignatureFailure);
        }
        if validation_failures.is_empty() {
            Ok(())
        } else {
            Err(ValidationFailure::new(validation_failures))
        }
    }

    fn signature_verifies(&self) -> bool {
        match self.data() {
            Ok(data) => self
                .issuer_public_key()
                .verify(&data, self.signature())
                .is_ok(),
            Err(_) => false,
        }
    }
}
