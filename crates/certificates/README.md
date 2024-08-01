# Certificates and tokens

## Contents

* [Overview](#overview)
* [Keys](#keys)
* [The distinction between certificates and tokens](#the-distinction-between-certificates-and-tokens)
* [Certificates](#certificates)
  * [Certificate role](#certificate-role)
  * [Certificate hierarchy](#certificate-hierarchy)
  * [Creating certificate requests](#creating-certificate-requests)
  * [Certificate bundles](#certificate-bundles)
  * [Issuing certificates](#issuing-certificates)
  * [Cross-signed certificates](#cross-signed-certificates)
  * [Additional fields on exemption certificates](#additional-fields-on-exemption-certificates)
* [Tokens](#tokens)
  * [Token Bundles](#token-bundles)
  * [Exemption Tokens](#exemption-tokens)
    * [Setting `emails_to_notify` on an exemption token](#setting-emails_to_notify-on-an-exemption-token)
    * [Issuing 'child' exemption tokens from a 'parent' exemption token](#issuing-child-exemption-tokens-from-a-parent-exemption-token)
  * [Database Tokens](#database-tokens)
  * [HLT Tokens](#hlt-tokens)
  * [Keyserver Tokens](#keyserver-tokens)
  * [Synthesizer Tokens](#synthesizer-tokens)
* [Serialization](#serialization)
  * [Keypair](#keypair)
  * [Certificate](#certificate)
  * [Token](#token)
* [Validating a certificate or token](#validating-a-certificate-or-token)
* [Design overview](#design-overview)

## Overview

This project provides the ablilty to create a chain of certificates for use in verifying the data integrity of exemption tokens and other token types.

## Keys

Certificates have associated keys which allow them to create verifiable signatures when issuing their own certificates or tokens. Most token types also have associated keys for authentication purposes. The digital signature algorithm used is `ed25519`.

## The distinction between certificates and tokens

Tokens hold information that is critical to the correct operation of the SecureDNA system. Each token type serves a specific purpose, such as identifying authorized synthesizer machines or detailing exemptions to synthesis restrictions. The accuracy of the information held in tokens is essential; accidental alterations or misinformation by malicious individuals could lead to screening failures. To ensure that a token's contents originate from an authorized source, we rely on certificates. Unlike tokens, certificates do not directly provide operational information to the system. However, by tracing a token’s chain of issuance back through a chain of certificates to a trusted root, we can verify the authenticity of the information held in the token.

The implementation permits each token to have fully customized fields tailored to its specific use case. This flexibility in token composition minimizes the need to handle special cases within certificates, limiting the variety of fields they require and enhancing security.

## Certificates

### Certificate role

All certificates will have one of three different roles. The type of certificate or token that can be issued by a certificate is constrained by its role. Certificates are only able to issue other certificates that have the same role.

The three possible roles are:

* `exemption`: responsible for issuing exemption tokens
* `infrastructure`: responsible for issuing tokens for use within the SecureDNA infrastructure
* `manufacturer`: responsible for issuing tokens to identify synthesizer machines

### Certificate hierarchy

Certificates are able to issue new certificates from certificate requests according to the following constraints:

* root certificates are able to self sign and can issue intermediate certificates.
* intermediate certificates can issue other intermediate certificates and also leaf certificates.
* leaf certificates can issue tokens from token requests.

### Creating certificate requests

When creating a certificate request a role and public key must be provided. To create a root exemption certificate request:

```rust
let root_keypair = KeyPair::new_random();
let root_req = RequestBuilder::<Exemption>::root_v1_builder(root_keypair.public_key()).build();
```

To save the associated keypair in an encrypted format:

```rust
let mut key_backup = Vec::new();
let root_req = keypair.write_key(&mut key_backup, "passphrase")?;
```

### Self-signing root certificates

A root certificate request is able to self sign as follows:

```rust
let root_cert = root_req.load_key(&keypair)?.self_sign(IssuerAdditionalFields::default())?;
```

### Certificate Bundles

In order to show the provenance of a certificate we need to be able to store the certificate alongside its `CertificateChain` - all the issuing certificates required to be able to trace a path back to the root certificate. The `CertificateBundle` structure is used for this purpose.
The certificate bundle holds the main certificate(s) (multiple in the case of cross signed certificates) and its certificate chain.

```rust
    // A root certificate bundle does not have a chain.
    let root_bundle = CertificateBundle::new(root_cert, None);
```

### Issuing certificates

For convenience, we interact directly with the certificate bundle when issuing new certificates. The newly issued certificate bundle inherits the entire certificate chain from the parent bundle, with the addition of the parent certificate. This approach both minimises the amount of code that a user needs to write, and removes the risk of errors in specifying the certificate's chain.

```rust
let intermediate_keypair = KeyPair::new_random();
let intermediate_req = RequestBuilder::<Exemption>::intermediate_v1_builder(intermediate_keypair.public_key())
    .build()

let intermediate_bundle = root_bundle.issue_cert_bundle(intermediate_req, IssuerAdditionalFields::default(), root_keypair)?;
```

The struct `IssuerAdditionalFields` is used to provide fields added by the certificate issuer.

IssuerAdditionalFields can be modified to set how long the certificate will be valid for, or to add email addresses to be notified on the use of an exemption token.

```rust
let issuer_fields = IssuerAdditionalFields::default()
    .with_expiry_in_days(90)
    .with_emails_to_notify(vec!["a@example.com", "b@example.com"])
```

If no expiration date is provided through the use of `with_expiry_in_days`, the certificate will expire in exactly 28 days.

### Cross-signed certificates

In order to add redundancy to a certificate chain we may want to create cross-signed certificates by having a certificate request signed by more than one certificate.

### Additional fields on exemption certificates

Certificates hold the majority of their fields in common but exemption certificates contain the extra fields `orcid_id`, `emails_to_notify` and `allow_blinding` (actually the first two of these exist on all certificates but can only be set on exemption certificates). The purposes of these fields are as follows:

* `orcid_id`: orcid id of the certificate owner
* `emails_to_notify`: determines the emails that must be notified when a exemption token is used (see details below)
* `allow_blinding`: whether a certificate is able to issue a exemption in which the shipping addresses are hidden

## Tokens

Tokens are issued by leaf certificates. There are five different types of tokens, which are issued by certificates with roles as follows:

* `Exemption`
  * exemption token
    * some exemption tokens can issue further exemption tokens
* `Infrastructure`
  * database token
  * HLT token
  * keyserver tokens
* `Manufacturer`
  * synthesizer token

### Token Bundles

We can show the provenance of a token by using the `TokenBundle` struct.
The token bundle holds a token and its chain which contains the items necessary to trace its issuance back to the root certificate.

All tokens bundles with the exception of exemption tokens have a chain which contains only certificates. Exemption tokens can be issued by a 'parent' exemption token, so their chains can also contain exemption tokens.

### Exemption Tokens

An exemption token request can be created and issued by an exemption leaf certificate bundle as follows:

```rust
    let exemption = Organism::new(
        "Chlamydia psittaci",
        vec![
            SequenceIdentifier::Id(GenbankId::try_new("1112252")?),
            SequenceIdentifier::Id(GenbankId::try_new("1112253")?),
            SequenceIdentifier::Dna(Sequence::try_new(
                    ">Virus1\nAC\nT\n>Empty\n\n>Virus2\n>with many\n>comment lines\nC  AT",
                )?),
        ],
    );
    let requestor = Description::default()
        .with_name("some researcher")
        .with_email("email@example.com");

    let auth_device =
    Authenticator::Yubikey(YubikeyId::try_new("cccjgjgkhcbb")?);

    let shipping_address = vec!["19 Some Street".to_string(), "Some City".to_string()];

    let etr = ExemptionTokenRequest::v1_token_request(
        None,
        vec![exemption],
        requestor,
        vec![auth_device],
        vec![shipping_address],
    );

    // Authenticators added by token issuer, if any.
    let issuer_auth_devices = Vec::new();

    let et_bundle = leaf_cert_bundle
        .issue_exemption_token_bundle(etr, Expiration::expiring_in_days(90).unwrap(), issuer_auth_devices, leaf_keypair)?;
```

If no expiration date is provided through the use of `Expiration::expiring_in_days`, the token will expire in exactly 28 days.

#### Setting `emails_to_notify` on an exemption token

The exemption token includes a field called emails_to_notify, whose contents are derived from the leaf certificate that issued the token. Both the requestor of the leaf certificate and its issuer (an intermediate certificate holder) can specify email addresses. These addresses will be copied to any exemption token issued by the leaf certificate. If the token itself issues an exemption token, these values will be copied again to the child token.

#### Issuing 'child' exemption tokens from a 'parent' exemption token

A 'parent' exemption token which is capable of issuing further exemption tokens can be created by supplying a public key when creating the exemption token request.
The parent token should be issued as normal by an exemption leaf certificate.

```rust
    let et_keypair = KeyPair::new_random();
    let parent_etr = ExemptionTokenRequest::v1_token_request(
        Some(keypair.public_key()),
        vec![exemption],
        requestor,
        vec![auth_device],
        vec![shipping_address],
    );

    let parent_et_bundle = leaf_cert_bundle
        .issue_exemption_token_bundle(parent_etr, Expiration::expiring_in_days(90).unwrap(), issuer_auth_devices, leaf_keypair)?;
```

A further exemption token can be issued from the resulting exemption token bundle as follows.

```rust
    let child_et_bundle = parent_et_bundle
                    .issue_exemption_token_bundle(child_etr, Expiration::expiring_in_days(90).unwrap(), issuer_auth_devices, et_keypair)?;
```

The child exemption token will only be issued if the following requirements are fulfilled:

* the parent token has an associated keypair
* the child token request's exemptions are present on the parent token
* the child token request's shipping addresses are present on the parent token
* the child token request does not have an associated keypair of its own

In addition, on issuing the child token, any 'emails to notify' (emails which should be notified when a token is used) which are present on the parent token are copied to the child, along with any email associated with the parent token.

During validation of an exemption token's chain, compliance with the above rules will be checked. The presence of the parent token's email address in the 'emails to notify' field is not checked however, as its absence would not violate the constraints of the parent token.

### Database Tokens

Database tokens are used to identify and authorize instances of the HDB.
They are issued by infrastructure leaf certificate bundles as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = DatabaseTokenRequest::v1_token_request(kp.public_key());

let database_token_bundle = leaf_cert_bundle.issue_database_token_bundle(req, Expiration::default(), leaf_keypair)
```

### HLT Tokens

Hazard lookup table (HLT) tokens are used to identify and authorize instances of the hazard lookup table.
They are issued by infrastructure leaf certificate bundles as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = HltTokenRequest::v1_token_request(kp.public_key());

let hlt_token_bundle = leaf_cert_bundle.issue_hlt_token_bundle(req, Expiration::default(), leaf_keypair)
```

### Keyserver Tokens

Keyserver tokens are used to identify and authorize keyservers.
The are issued by infrastructure leaf certificate bundles as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = KeyserverTokenRequest::v1_token_request(kp.public_key(), KeyserverId::try_from(1).unwrap());

let keyserver_token_bundle = leaf_cert_bundle.issue_keyserver_token_bundle(req, Expiration::default(), leaf_keypair)
```

### Synthesizer Tokens

Synthesizer tokens are used to identify benchtop synthesizers.
They are issued by manufacturer leaf certificate bundles as follows:

```rust
let keypair = KeyPair::new_random();
let domain = "maker.synth";
let model = "XL";
let serial_number = "10AK";
let max_dna_base_pairs_per_day = 10_000_000u64;

let token_request = SynthesizerTokenRequest::v1_token_request(
    kp.public_key(),
    domain,
    model,
    serial_number,
    max_dna_base_pairs_per_day,
);

let synthesizer_token_bundle = leaf_cert_bundle.issue_synthesizer_token_bundle(req, Expiration::default(), leaf_keypair)
```

## Serialization

Certificate data is first serialized into a binary format based on the ASN.1 DER (Distinguished Encoding Rules) standard.
The result is then encoded in the PEM format: the binary data is base64-encoded and given a header and footer which describe the type of message encoded.

We use PEM-encoded ASN.1 DER in order to persist keys, certificate requests, certificate bundles, token requests and token bundles to file.

### Keypair

The public key is serialized to a file with a `.pub` extension; its hex encoding is prepended to the file for convenience.

The private key is encrypted before serialization via password-based encryption.
The file extension used is `.priv`.

### Certificate

The serialised forms of certificate bundles and certificate requests do not contain the associated private key.

Certificate request files have a `.certr` extension. Certificate bundles have a `.cert` extension. Note that the contents of this file is both the certificate and its chain; the certificate on its own is largely useless.

On retrieving a certificate bundle from file, the certificate's private key will need to be loaded from file in order to issue a certificate or token.

### Token

The serialised forms of token bundles and token requests do not contain the associated private key.

Token bundles and token requests are saved to files with the following extensions:

| Token type         | Request                | Token bundle         |
|--------------------|------------------------|----------------------|
| Exemption          | `.etr`                 | `.et`               |
| Keyserver          | `.ksr`                 | `.ks`                |
| Database           | `.dtr`                 | `.dt`                |
| HLT                | `.htr`                 | `.ht`                |
| Synthesizer        | `.str`                 | `.st`                |

On retrieving a token bundle from file, the token's private key will need to be loaded from file in order to create a signature.

Token bundles sent over the wire are ASN.1 DER encoded.

## Validating a certificate or token

In order to trust a certificate or token we want to be able to verify that they have been issued by a chain of certificates that can be traced back to a trusted root.

To verify this we can use the `validate_path_to_issuers` function. It looks for a path to an issuing public key using the depth-first search algorithm. It inspects the certificates in the certificate or token's chain to look for a valid path.

The `validate_path_to_issuers` function takes a vector of public keys which may have issued either the token or certificate, or an item higher up in the chain. An optional revocation list can be supplied which identifies revoked tokens and certificates via request id, issuance id or public key. If the list is present, the token or certificate and each item in its chain will be checked against the revocation list.

```rust
let path_exists = leaf_bundle.validate_path_to_issuers(
    &[*root_cert.public_key()],
    Some(revocation_list),
);
```

```rust
let path_exists = token_bundle.validate_path_to_issuers(
    &[*root_cert.public_key()],
    Some(revocation_list),
);
```

## Design overview

In order to allow for future changes to certificates and tokens we require a way of versioning them. It is important that for any certificate we know what fields to expect.

A related requirement is that we are able to deserialise a certificate without knowing what version we have in advance.

This has lead to a somewhat convoluted design in which we have inner and outer representations of a certificate (corresponding to the certificate/inner and certificate/outer modules).

The outer `Certificate` is a struct with a private enum `CertificateVersion` whose variants contain the inner certificate. Currently only this outer certificate is exposed to users of the certificates module. This is an attempt to restrict access to the version details until we find that we need to expose something, for the sake of a cleaner public interface.

Certificate requests and tokens are similarly composed in order to allow versioning and easy serialisation/deserialisation.
