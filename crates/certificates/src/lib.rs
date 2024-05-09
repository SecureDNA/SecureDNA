// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod asn;
mod certificate;
mod certificate_chain;
mod chain_item;
mod ecies;
mod error;
mod format;
mod issued;
mod key_state;
mod keypair;
mod pem;
mod shared_components;
mod tokens;
mod traversal;
mod utility;
mod validation_failure;

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
pub use chain_item::ChainItem;
pub use ecies::EncryptionPublicKey;
pub use error::{DecodeError, EncodeError};
pub use format::{
    format_multiple_items, FormatError, FormatMethod, FormatMethodParseError, Formattable,
};
pub use issued::Issued;
pub use shared_components::common::{Description, Expiration, ExpirationError, Id};
pub use shared_components::role::{
    Exemption, Infrastructure, Manufacturer, Role, RoleKind, RoleKindParseError,
};
pub use tokens::exemption::{
    authenticator::{Authenticator, YubikeyId},
    exemption_list::{ExemptionListToken, ExemptionListTokenGroup, ExemptionListTokenRequest},
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
pub use traversal::ChainTraversal;
pub use utility::now_utc;
pub use validation_failure::{EXPIRED_TEXT, INVALID_SIGNATURE_TEXT, NOT_YET_VALID_TEXT};

mod chain;
pub mod file;
pub mod key_traits;
pub mod revocation;
pub mod test_helpers;
