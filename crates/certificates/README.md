# Certificates

This project provides the ablilty to create a chain of certificates for use in verifying the data integrity of exemption list tokens (ELTs) and other token types. 

The digital signature algorithm used by the certificates is ed25519.

## Certificate roles

All certificates will have one of three different roles. The type of token that can be issued by a certificate is constrained by its role. Certificates are only able to issue other certificates that have an identical role.

The three possible roles are:

- exemption (the certificate chain with this role is responsible for issuing exemption list tokens)
- infrastructure (the certificate chain with this role is responsible for issuing tokens for use within the SecureDNA infrastructure)
- manufacturer (the certificate chain with this role is responsible for issuing tokens to identify synthesizer machines)

## Certificate hierarchy

Certificates are able to issue new certificates from certificate requests according to the following constraints:

- root certificates are able to self sign and can issue intermediate certificates.
- intermediate certificates can issue other intermediate certificates and also leaf certificates.
- leaf certificates can issue tokens from token requests.

## Creating certificate requests
When creating a certificate request a role and public key must be provided. To create a root exemption certificate request: 

```rust
let keypair = KeyPair::new_random();
let root_req = RequestBuilder::<Exemption>::root_v1_builder(keypair.public_key()).build();
```

To save the associated keypair in an encrypted format:

```rust
let mut key_backup = Vec::new();
let root_req = keypair.write_key(&mut key_backup, "passphrase")?;
```

## Availability of the private key

The serialised forms of certificates and certificate requests intentionally do not contain details of the private key.
On deserialising a certificate, its private key will need to be loaded in order to issue a new certificate.

```rust
let root_cert = root_cert.load_key(&key_backup)?;
```

Certificates and certificate requests are not able to be cloned when in a state in which the private key is available. In order to clone a certificate `into_key_unavailable()` should be called. 

```rust
let root_cert = root_cert.into_key_unavailable();
```

## Serialising certificates and certificate requests

We use two types of encoding for certificates and tokens, ASN.1 DER and PEM.
ASN.1 DER (Distinguished Encoding Rules) is a standard for encoding data into a binary format.
The PEM format encodes binary data using base64. It contains a header and footer which describe the type of message encoded.

Certificates and certificate request can be serialised into and deserialised from PEM encoded ASN.1 DER.  

This is to avoid the posibility of being able to serialise the private key, as these types cannot contain private key information. No information about the private key will be encoded, regardless of whether the certificate has a private key available when it is encoded.

The certificates and certificate requests will be in the `KeyUnavailable` state after being decoded, regardless of their state when encoded.

When deserializing a certificate, its role must be provided, however its key status can be left to be inferred.

```rust
let encoded = req.to_pem()?;
let decoded = CertificateRequest::<Infrastructure, KeyUnavailable>::from_pem(encoded)?;
```

```rust
let encoded = cert.to_pem()?;
let decoded = Certificate::<Manufacturer, _>::from_pem(encoded)?;
```

## Issuing certificates from certificate requests

A new certificate can be issued from a certificate request provided the hierarchy contraints stated above are followed.
The struct `IssuerAdditionalFields` is used to provide fields added by the certificate issuer.

```rust
let keypair = KeyPair::new_random();
let intermediate_req = RequestBuilder::<Exemption>::intermediate_v1_builder(keypair.public_key())
    .build()

let intermediate_cert = root_cert.issue_cert(intermediate_req, IssuerAdditionalFields::default())?;
```

IssuerAdditionalFields can be modified to set how long the certificate will be valid for, or to add email addresses to be notified on the use of an ELT.

```rust
let issuer_fields = IssuerAdditionalFields::default()
    .with_expiry_in_days(90)
    .with_emails_to_notify(vec!["a@example.com", "b@example.com"])
```

## Cross-signed certificates

In order to add redundancy to a certificate chain we may want to create cross-signed certificates by having a certificate request signed by more than one certificate.

## Certificate Bundles

In order to show the provenance of a certificate we need to be able to store the certificate alongside its `CertificateChain` - all the issuing certificates required to be able to trace a path back to the root certificate. The `CertificateBundle` structure is used for this purpose. 
The certificate bundle holds the main certificate(s) (multiple in the case of cross signed certificates) and its certificate chain.

```rust
    // An intermediate certificate bundle does not need a chain as the root certificate's public key is known.
    let int_cert_bundle = CertificateBundle::new(intermediate_cert, None);

    // The issuing certificate is able to create a chain for the certificates it issues.
    let root_chain = int_cert_bundle.issue_chain();

    let leaf_bundle = CertificateBundle::new(leaf_cert, Some(chain));
```

### Finding a valid path from a certificate to a root certificate

In order to trust a certificate we want to be able to verify that it has been issued by a chain of certificates that can be traced back to a known root.

To verify this we can use the `path_to_issuer_exists` function. It looks for a path to a known certificate issuer using the depth-first search algorithm. It inspects the certificates in the certificate bundle's chain to look for a valid path.

```rust
let path_exists = leaf_bundle.path_to_issuers_exists_for_cert(
    &[*root_cert.public_key()],
);
``` 

## Issuing Tokens

Tokens are issued by leaf certificates. There are five different types of tokens, which are issued by certificates with roles as follows:

`Exemption` - Exemption List Tokens
`Infrastructure` - Database Tokens, HLT Tokens, Keyserver Tokens
`Manufacturer` - Synthesizer Tokens

### Exemption List Tokens

An ELTR can be created and issued by an exemption leaf certificate as follows:

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

    let eltr = ExemptionListTokenRequest::v1_token_request(
        None,
        vec![exemption],
        requestor,
        vec![auth_device],
        vec![shipping_address],
    );

    // Authenticators added by token issuer, if any.
    let issuer_auth_devices = Vec::new();

    leaf_cert
        .issue_elt(eltr, Expiration::expiring_in_days(90).unwrap(), issuer_auth_devices)?;
    
```

#### Issuing 'child' exemption list tokens from a 'parent' exemption list token

A 'parent' exemption list token which is capable of issuing further exemption list tokens can be created by supplying a public key when creating the exemption list token request. 
The parent token should be issued as normal by an exemption leaf certificate.

```rust
    let keypair = KeyPair::new_random();
    let parent_eltr = ExemptionListTokenRequest::v1_token_request(
        Some(keypair.public_key()),
        vec![exemption],
        requestor,
        vec![auth_device],
        vec![shipping_address],
    );
```

Tokens can be issued from this exemption list token as follows.

```rust
    let child_elt = parent_elt
                    .load_key(keypair)
                    .unwrap()
                    .issue_elt(child_eltr, Expiration::expiring_in_days(90).unwrap(), issuer_auth_devices)?;
```

The child exemption list token will only be issued if the following requirements are fulfilled:

    - the parent token has an associated keypair
    - the child token request's exemptions are present on the parent token
    - the child token request's shipping addresses are present on the parent token
    - the child token request does not have an associated keypair of its own

In addition, on issuing the child token, any 'emails to notify' (emails which should be notified when a token is used) which are present on the parent token are copied to the child, along with any email associated with the parent token.

During validation of an exemption list token's chain, compliance with the above rules will be checked. The presence of the parent token's email address in the 'emails to notify' field is not checked however, as its absence would not violate the constraints of the parent token.

### Database Tokens

Database tokens are used to identify and authorize instances of the HDB.
They are issued by infrastructure leaf certificates as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = DatabaseTokenRequest::v1_token_request(kp.public_key());

let token = leaf_cert.issue_database_token(req, Expiration::default())
```

### HLT Tokens

HLT tokens are used to identify and authorize instances of the hazard lookup table.
They are issued by infrastructure leaf certificates as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = HltTokenRequest::v1_token_request(kp.public_key());

let token = leaf_cert.issue_hlt_token(req, Expiration::default())
```

### Keyserver Tokens

Keyserver tokens are used to identify and authorize keyservers.
The are issued by infrastructure leaf certificates as follows:

```rust
let keypair = KeyPair::new_random();
let token_request = KeyserverTokenRequest::v1_token_request(kp.public_key(), KeyserverId::try_from(1).unwrap());

let token = leaf_cert.issue_keyserver_token(req, Expiration::default())
```

### Synthesizer Tokens

Synthesizer tokens are used to identify benchtop synthesizers.
They are issued by manufacturer leaf certificates as follows:

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

let token = leaf_cert.issue_synthesizer_token(req, Expiration::default())
```
## Token Bundles

We can show the provenance of a token by using the `TokenBundle` struct. 
The certificate bundle holds the token and its certificate chain.

```rust
    // The issuing leaf certificate is able to create a chain for the tokens it issues.
    let token_chain = leaf_cert_bundle.issue_chain();

    let token_bundle = TokenBundle::new(token, token_chain);
```

# Design overview

In order to allow for future changes to certificates and ELTs we require a way of versioning them. It is important that for any certificate we know what fields to expect. 

A related requirement is that we are able to deserialise a certificate without knowing what version we have in advance. 

This has lead to a somewhat convoluted design in which we have inner and outer representations of a certificate (corresponding to the certificate/inner and certificate/outer modules).

The outer `Certificate` is a struct with a private enum `CertificateVersion` whose variants contain the inner certificate. Currently only this outer certificate is exposed to users of the certificates module. This is an attempt to restrict access to the version details until we find that we need to expose something, for the sake of a cleaner public interface.

Certificate requests and tokens are similarly composed in order to allow versioning and easy serialisation/deserialisation.
