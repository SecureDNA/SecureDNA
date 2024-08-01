// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod asn;
mod certificate;
mod certificate_chain;
mod chain_item;
mod digest;
mod display;
mod ecies;
mod error;
mod issued;
mod key_state;
mod keypair;
mod pem;
mod shared_components;
mod tokens;
mod traversal;
mod utility;
mod validation_error;

pub use crate::keypair::{
    KeyLoadError, KeyPair, KeyWriteError, PublicKey, Signature, SignatureVerificationError,
};
pub use key_state::{KeyAvailable, KeyMismatchError, KeyUnavailable};

pub(crate) use crate::pem::MultiItemPemBuilder;
pub use crate::pem::{PemDecodable, PemEncodable};
pub use certificate::certificate_bundle::{CertificateBundle, CertificateBundleError};
pub use certificate::{
    Builder, Certificate, CertificateDigest, CertificateRequest, HierarchyKind,
    HierarchyKindParseError, IssuanceError, IssuerAdditionalFields, RequestBuilder, RequestDigest,
};
pub use certificate_chain::CertificateChain;
pub use chain_item::{ChainItem, ChainItemDigest, ChainItemDigestValidationError};
pub use digest::Digestible;
pub use ecies::EncryptionPublicKey;
pub use error::{DecodeError, EncodeError};
pub use issued::Issued;
pub use shared_components::common::{Description, Expiration, ExpirationError, Id};
pub use shared_components::role::{
    Exemption, Infrastructure, Manufacturer, Role, RoleKind, RoleKindParseError,
};
pub use tokens::exemption::{
    authenticator::{Authenticator, YubikeyId},
    et::{ExemptionToken, ExemptionTokenGroup, ExemptionTokenRequest},
    organism::{GenbankId, Organism, Sequence, SequenceIdentifier},
};
pub use tokens::infrastructure::{
    database::{DatabaseToken, DatabaseTokenGroup, DatabaseTokenRequest},
    hlt::{HltToken, HltTokenGroup, HltTokenRequest},
    keyserver::{KeyserverToken, KeyserverTokenGroup, KeyserverTokenRequest},
};
pub use tokens::manufacturer::synthesizer::{
    AuditRecipient, SynthesizerToken, SynthesizerTokenGroup, SynthesizerTokenRequest,
};
pub use tokens::token_bundle::{TokenBundle, TokenBundleError};
pub use tokens::{Request, TokenGroup, TokenKind};
pub use traversal::{ChainTraversal, ChainValidationError};
pub use utility::now_utc;
pub use validation_error::{
    ValidationError, EXPIRED_TEXT, INVALID_SIGNATURE_TEXT, NOT_YET_VALID_TEXT,
};

mod chain;
pub mod file;
pub mod issuance_checks;
pub mod key_traits;
pub mod revocation;
pub mod test_helpers;
