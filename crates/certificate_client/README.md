# Certificate CLI
## `env_passphrase` feature

If necessary for development purposes, the `env_passphrase` feature can be enabled. When this feature is enabled any key encryption passphrases will be set via the `SECUREDNA_CERT_KEY_ENCRYPTION_PASSPHRASE` environment variable.

## Faketime

Tests for the below CLIs require the installation of the `faketime` utility tool.

## Keypair creation

Generating a SecureDNA key. This tool will create a file with a .priv extension containing the encrypted private key.
It will also create a file with a .pub file containing the public key. The first line of the .pub file is the hex representation of the public key, the remaining lines are the PEM encoding of the public key.

### Usage:
    sdna-create-key [OPTIONS]

### Options
    --key-dest     <KEY DESTINATION>  Filepath where the keypair will be saved (optional).
                               If this is not provided ~/SecureDNA will be used
    -h, --help                 Print help
    -V, --version              Print version

## Certificate request creation

Generating a SecureDNA certificate request

### Usage:
    sdna-create-cert <ROLE> <HIERARCHY> [OPTIONS]
### Arguments:
    <ROLE>          Role of certificate [possible values: exemption, infrastructure, manufacturer]
    <HIERARCHY>     Hierarchy level of certificate [possible values: root, intermediate, leaf]
### Options:
    --name <NAME>                               Name of certificate creator (optional)
    --email <EMAIL>                             Email of certificate creator (optional)
    --notify <EMAIL>                            Email(s) to be notified when an exemption token issued by this cert is used (optional, only for exemption leaf certs).
                                                Provide one email address per use, e.g. "--notify a@example.com --notify b@example.com".
    --allow-blinding                            Determines whether the certificate is able to issue blinded certificates or exemption tokens (optional, only for exemption certs).
    --output <REQUEST FILE DESTINATION>         Filepath where the certificate request will be saved (optional).
                                                If this is not provided ~/SecureDNA will be used.
    --create-new-key <KEY DESTINATION>          Filepath where the private key will be saved (optional).
                                                If this is not provided ~/SecureDNA will be used
    --key-from-file <KEY FILE PATH>             Path to .pub file (optional)
    --key-from-hex <KEY_FROM_HEX>               Hex representation of public key (optional, found inside the .pub file on the first line)
    -h, --help                                  Print help information
    -V, --version                               Print version information

If none out of [--create-new-key, --key-from-file, --key-from-hex] are used then a new key will be created and saved in ~/SecureDNA.

### Example:
    sdna-create-cert exemption root --name "E Xample" --email "e.xample@example.com"

## Token request creation

Generating a SecureDNA token request

### Usage:
    sdna-create-token [GENERAL OPTIONS] <TOKEN TYPE> [TOKEN SPECIFIC OPTIONS]
Note that for this tool the general options must appear before the token type and the token specific options.

### Arguments:
    <TOKEN TYPE>                Type of token [possible values: keyserver, database, hlt, synthesizer]

### General options (available on all tokens):
    --output <REQUEST FILE DESTINATION>         Filepath where the certificate request will be saved (optional).
                                                If this is not provided ~/SecureDNA will be used.
    --create-new-key <KEY DESTINATION>          Filepath where the private key will be saved (optional).
                                                If this is not provided ~/SecureDNA will be used
    --key-from-file <KEY FILE PATH>             Path to .pub file (optional)
    --key-from-hex <KEY_FROM_HEX>               Hex representation of public key (optional, found inside the .pub file on the first line)
    -h, --help                                  Print help information
    -V, --version                               Print version information

If none out of [--create-new-key, --key-from-file, --key-from-hex] are used then a new key will be created and saved in ~/SecureDNA.

### Keyserver token options
    --keyserver-id <KEYSERVER_ID>  Keyserver ID, this corresponds to the index of the keyserver's keyshare

### Synthesizer token options
    --domain <DOMAIN>
        The domain name of the manufacturer
    --model <MODEL>
        The machine model name or number
    --serial <SERIAL>
        The machine serial number
    --rate-limit <RATE_LIMIT>
        The expected maximum rate at which this machine can synthesize DNA, in nucleotides per day
    --audit-email <AUDIT_EMAIL>
        Email of the audit recipient (optional).
    --audit-public-key <AUDIT_PUBLIC_KEY>
        Public key of the audit recipient (optional). Expects a hex encoded secp256k1 public key

The database and HLT tokens have no custom options.

### Examples:

    sdna-create-token keyserver --id 1
    sdna-create-token database
    sdna-create-token hlt
    sdna-create-token synthesizer --domain X.Y.Z --model X10L --serial pO4567 --rate-limit 100000 --audit-email a@example.com --audit-public-key 03f29057c21d3eb14815eefa0127895b57278fd41c2bad78861ff7a5b1c9b5adae

## Certificate inspection

Inspecting and validating a SecureDNA certificate or certificate request

### Usage:
    sdna-inspect-cert <ROLE> <INSPECTION TARGET COMMAND> <FILE> [OPTIONS]

### Arguments:
    <ROLE>                      Role of certificate [possible values: exemption, infrastructure, manufacturer]
    <INSPECTION TARGET COMMAND>
    <FILE>                      Path of certificate or certificate request to be inspected

### Inspection target commands:
    request  Inspect a certificate request
    cert     Inspect a certificate
    chain    Inspect a certificate chain

#### Usage:
    sdna-inspect-cert <ROLE> request <FILE>
    sdna-inspect-cert <ROLE> cert <FILE>
    sdna-inspect-cert <ROLE> chain <FILE> <CHAIN VIEW COMMAND>

#### Chain view commands:
    all-certs         View all certificates in the supplied chain, regardless of whether they are valid
    all-paths         View all valid paths through the chain certificates to an issuer with a matching public key
    not-part-of-path  Any certificates in the supplied chain that do not form part of a valid path

#### **all-certs**
View all certificates in the supplied chain, regardless of whether they are valid

    sdna-inspect-cert <ROLE> chain <FILE> all-certs

#### **all-paths**
View all valid paths through the chain certificates to an issuer with a matching public key.
One or more public keys can be supplied.

    sdna-inspect-cert <ROLE> chain <FILE> all-paths [PUBLIC_KEYS]...

#### **not-part-of-path**
Any certificates in the supplied chain that do not form part of a valid path to an issuer with a matching public key. One or more public keys can be supplied.

    sdna-inspect-cert <ROLE> chain <FILE> not-part-of-path [PUBLIC_KEYS]...

### Options:
    --format <FORMAT>       How to format the certificate, certificate request, or chain display
                            [default: plain-digest] [possible values: plain-digest, json-digest, json-full]
    -h, --help              Print help information
    -V, --version           Print version information

### Examples:
    sdna-inspect-cert exemption request ~/SecureDNA/b1d012e221d4fc54e4e43a31fd79cbbf-root.certr

    sdna-inspect-cert manufacturer cert ~/SecureDNA/cc6a2aecf9f2288802724994b285bc17-leaf.cert

    sdna-inspect-cert infrastructure chain ~/SecureDNA/cc6a2aecf9f2288802724994b285bc17-leaf.cert all-certs

    sdna-inspect-cert exemption chain ~/SecureDNA/cc6a2aecf9f2288802724994b285bc17-leaf.cert all-paths 88f83584965361d534a0703bb1c24a4d781958eb4325d7c97adc24ff1b005980

    sdna-inspect-cert manufacturer chain ~/SecureDNA/cc6a2aecf9f2288802724994b285bc17-leaf.cert not-part-of-path 88f83584965361d534a0703bb1c24a4d781958eb4325d7c97adc24ff1b005980 be3f1e71302e2aa402f793be2603da449a648d9329bca89c154d112d99c2c515

## Token inspection

Inspecting and validating a SecureDNA token or token request

### Usage:
    sdna-inspect-token <TOKEN TYPE> <INSPECTION TARGET COMMAND> <FILE> [OPTIONS]

### Arguments:
    <TOKEN TYPE>                Type of token [possible values: keyserver, database, hlt, synthesizer]
    <INSPECTION TARGET COMMAND>
    <FILE>                      Path of token or token request to be inspected

### Inspection target commands:
    request  Inspect a token request
    token    Inspect a token
    chain    Inspect token's certificate chain

#### Usage:
    sdna-inspect-token <TOKEN TYPE> request <FILE>
    sdna-inspect-token <TOKEN TYPE> cert <FILE>
    sdna-inspect-token <TOKEN TYPE> chain <FILE> <CHAIN VIEW COMMAND>

### Chain view commands
See sdna-inspect-cert

### Examples:
    sdna-inspect-token keyserver request ~/SecureDNA/keyserver.ktr

    sdna-inspect-token keyserver token ~/SecureDNA/keyserver.kt

    sdna-inspect-token keyserver chain ~/SecureDNA/keyserver.kt all-certs

    sdna-inspect-token keyserver chain ~/SecureDNA/keyserver.kt all-paths 88f83584965361d534a0703bb1c24a4d781958eb4325d7c97adc24ff1b005980

    sdna-inspect-token keyserver chain ~/SecureDNA/keyserver.kt not-part-of-path 88f83584965361d534a0703bb1c24a4d781958eb4325d7c97adc24ff1b005980

## Certificate signing
Signing a SecureDNA certificate request

### Usage:
#### Signing another cert:
    sdna-sign-cert <ROLE> sign <REQUEST FILE> <CERT FILE> [OPTIONS]
#### Self signing a root request:
    sdna-sign-cert <ROLE> self-sign <REQUEST FILE> [OPTIONS]

### Options
    --key <KEY>                 Filepath where issuer's private key can be found (optional).
                                If this is not provided an attempt will be made to infer by using the filepath of the certificate
    --notify <EMAIL>            Email(s) to be notified when an exemption token issued by this cert is used (optional, only for leaf certs)
                                Provide one email address per use, e.g. "--notify a@example.com --notify b@example.com".
    --days-valid <DAYS_VALID>   How many days after today the certificate will be valid for (optional, default is 28)
    --output <CERT DESTINATION> Filepath where new certificate will be saved (optional).
                                If this is not provided the path will be derived from the request path.
    -h, --help                  Print help information
    -V, --version               Print version information

### Example:

    sdna-sign-cert exemption sign ~/SecureDNA/cc6a2aecf9f2288802724994b285bc17-leaf.certr ~/SecureDNA/c57aa1ee46fd186fb2f057cf936fa72c-int.cert --days-valid 60

    sdna-sign-cert infrastructure self-sign ~/SecureDNA/b1d012e221d4fc54e4e43a31fd79cbbf-root.certr

## Token signing
Signing a SecureDNA token request

### Usage:
    sdna-sign-token <TOKEN TYPE> <REQUEST FILE> <CERT FILE> [OPTIONS]

### Example:

    sdna-sign-token database ~/SecureDNA/db.dtr ~/SecureDNA/leaf.cert

### Options
    --key <KEY>                     Filepath where issuer's private key can be found (optional).
                                    If this is not provided an attempt will be made to infer by using the filepath of the certificate
    --days-valid <DAYS_VALID>       How many days after today the certificate will be valid for (optional, default is 28)
    --output <TOKEN DESTINATION>    Filepath where new token will be saved (optional).
                                    If this is not provided the path will be derived from the request path.
    -h, --help                      Print help information
    -V, --version                   Print version information

## Retrieve certificate request from certificate
Retrieves the original certificate request from a certificate. This could be useful in creating a cross signed certificate where the original certificate request has been discarded.

### Usage:
    sdna-retrieve-cert-request [OPTIONS] <ROLE> <CERT>

### Arguments:
    <ROLE>  Role of certificate [possible values: exemption, infrastructure, manufacturer]
    <CERT>  Filepath where certificate can be found

### Options:
    --output <OUTPUT>  Filepath where the request will be saved (optional). If this is not provided it will be derived from the certificate filepath
    -h, --help             Print help
    -V, --version          Print version

## Merge certificate files
A tool to merge two certificate files which are derived from the same certificate request and have the same role.

### Usage:
    sdna-merge-cert <ROLE> <CERT_1> <CERT_2> [OPTIONS]

### Options:
    --output <CERT DESTINATION>     Filepath where new certificate will be saved (optional).
                                    If this is not provided ~/SecureDNA will be used.
    -h, --help                      Print help
    -V, --version                   Print version

### Example:

    sdna-merge-cert infrastructure ~/SecureDNA/cert_a.cert ~/SecureDNA/cert_b.cert

## Default Filenames

When specific filenames are not provided using the `--output` argument, these programs automatically generate default filenames for keys, certificates, and tokens. This section outlines how these filenames are derived.

### Keys

The default filenames for keys are generated from the first 16 characters of the public key’s hex encoding:

- **Private Key**: `[first 16 hex chars].priv`
- **Public Key**: `[first 16 hex chars].pub`

### Certificates

For certificate requests and issuance, the filenames are based on the request ID, the certificate hierarchy type, and the date.

- **Certificate Request Filename**: `[request id]-[hierarchy type]-[date].certr`
- **Certificate Bundle Filename**: `[certificate request filename].cert`

### Tokens

Token filenames follow a similar pattern, incorporating the request ID and the date.

- **Token Request Filename**: `[request id]-[date].[token request extension]`
- **Token Bundle Filename**: `[token request filename].[token bundle extension]`

The extensions used for each token type are found [here](../certificates/README.md#token).

### Format options

The options for the `--format` argument are as follows:

- **plain-digest**: Plain text with a digest of the certificate. This will be used if `--format` is not provided.
- **json-digest**: JSON with a digest of the certificate
- **json-full**: JSON with the full certificate

If the item being inspected is a token or certificate, then any associated validation errors will be included in the output.
Example outputs are as follows:

#### plain-digest

    V1 Keyserver Token
    Issuance ID:
        dbea5a89e1d22f5da9875fa6118930ee
    Request ID:
        8a15ba14b01bcc6bf9874ea7025fd6fd
    Public Key:
        6b09d302398e946b0572e24f7d8102821596e1de28025431c75d177bcb85e5bb
    Keyserver ID:
        1
    Issued by:
        (public key: b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4)
    Issued on:
        Thu, 06 Jun 2024 12:00:10 +0000
    Expires:
        Thu, 04 Jul 2024 12:00:10 +0000
    Signature:
        7669b2f8459d2f08b5d3858a2ca1db4dce71cbfc9fbc7ffe2049ac9fac8fe70bd46973fe2e012303745ce0e8de2d74741c4e1a4250b9a91d7e4897ef757e000f
    INVALID: The signature failed verification

    Intermediate V1 Infrastructure Certificate
    Issuance ID:
        7484324db500fbde871b48df596c9376
    Request ID:
        e948818b34447a2d1781f97d5ea3177a
    Issued to:
        (public key: 0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21)
    Issued by:
        (public key: f4e460e96e48f97671ca523ac82e53387616e40b23a747251f56441e48fe8284)
    Issued on:
        Thu, 06 Jun 2024 12:00:10 +0000
    Expires:
        Thu, 04 Jul 2024 12:00:10 +0000
    Signature:
        a66c2dcd58e7c123f181dc006a177c94c88cc943cf13a7148c65a11623433434cfe4dea87ca01f0bddef03c9165d93beff61a493a260102d78064804ee5a3902

    Leaf V1 Infrastructure Certificate
    Issuance ID:
        d464b298c7f1fcc5666c284d014b6c48
    Request ID:
        473425035cb60ed3a55842d81ef4e05b
    Issued to:
        (public key: b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4)
    Issued by:
        (public key: 0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21)
    Issued on:
        Thu, 06 Jun 2024 12:00:10 +0000
    Expires:
        Thu, 04 Jul 2024 12:00:10 +0000
    Signature:
        23104c5abdfc6852cf5e71f6d835a9721dd31200de73f86de44674c61fa427d06373128574e5b3372d770484cc6e785ebeb55d451aa595720a2248ed1077bf03

#### json-digest

    [
    {
        "item": {
        "KeyserverToken": {
            "version": "V1",
            "request_id": "8a15ba14b01bcc6bf9874ea7025fd6fd",
            "issuance_id": "dbea5a89e1d22f5da9875fa6118930ee",
            "keyserver_id": 1,
            "public_key": "6b09d302398e946b0572e24f7d8102821596e1de28025431c75d177bcb85e5bb",
            "issued_by": {
            "pk": "b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4",
            "desc": ""
            },
            "expiration": {
            "not_valid_before": 1717675210,
            "not_valid_after": 1720094410
            },
            "signature": "7669b2f8459d2f08b5d3858a2ca1db4dce71cbfc9fbc7ffe2049ac9fac8fe70bd46973fe2e012303745ce0e8de2d74741c4e1a4250b9a91d7e4897ef757e000f"
        }
        },
        "error": {
        "causes": [
            "SignatureFailure"
        ]
        }
    },
    {
        "item": {
        "Certificate": {
            "version": "Intermediate V1 Infrastructure",
            "issued_to": {
            "pk": "0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21",
            "desc": ""
            },
            "request_id": "e948818b34447a2d1781f97d5ea3177a",
            "issued_by": {
            "pk": "f4e460e96e48f97671ca523ac82e53387616e40b23a747251f56441e48fe8284",
            "desc": ""
            },
            "issuance_id": "7484324db500fbde871b48df596c9376",
            "expiration": {
            "not_valid_before": 1717675210,
            "not_valid_after": 1720094410
            },
            "signature": "a66c2dcd58e7c123f181dc006a177c94c88cc943cf13a7148c65a11623433434cfe4dea87ca01f0bddef03c9165d93beff61a493a260102d78064804ee5a3902",
            "emails_to_notify": []
        }
        }
    },
    {
        "item": {
        "Certificate": {
            "version": "Leaf V1 Infrastructure",
            "issued_to": {
            "pk": "b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4",
            "desc": ""
            },
            "request_id": "473425035cb60ed3a55842d81ef4e05b",
            "issued_by": {
            "pk": "0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21",
            "desc": ""
            },
            "issuance_id": "d464b298c7f1fcc5666c284d014b6c48",
            "expiration": {
            "not_valid_before": 1717675210,
            "not_valid_after": 1720094410
            },
            "signature": "23104c5abdfc6852cf5e71f6d835a9721dd31200de73f86de44674c61fa427d06373128574e5b3372d770484cc6e785ebeb55d451aa595720a2248ed1077bf03",
            "emails_to_notify": []
        }
        }
    }
    ]

#### json-full

    [{"item":{"KeyserverToken":{"V1":{"data":{"request":{"guard":"KTR1","keyserver_id":1,"request_id":"8a15ba14b01bcc6bf9874ea7025fd6fd","public_key":"6b09d302398e946b0572e24f7d8102821596e1de28025431c75d177bcb85e5bb"},"issuer_fields":{"guard":"KTI1","issuance_id":"dbea5a89e1d22f5da9875fa6118930ee","identity":{"pk":"b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4","desc":""},"expiration":{"not_valid_before":1717675210,"not_valid_after":1720094410}}},"signature":"7669b2f8459d2f08b5d3858a2ca1db4dce71cbfc9fbc7ffe2049ac9fac8fe70bd46973fe2e012303745ce0e8de2d74741c4e1a4250b9a91d7e4897ef757e000f"}}},"error":{"causes":["SignatureFailure"]}},{"item":{"Certificate":{"IntermediateV1":{"data":{"hierarchy_level":{"guard":"INT1"},"role":"INFRASTRUCTURE","common":{"subject":{"guard":"SUBJECT1","request_id":"e948818b34447a2d1781f97d5ea3177a","pk":"0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21","requestor_desc":{"name":null,"email":null,"phone_number":null,"orcid":null},"emails_to_notify":[]},"issuer":{"guard":"ISSUER1","issuance_id":"7484324db500fbde871b48df596c9376","identity":{"pk":"f4e460e96e48f97671ca523ac82e53387616e40b23a747251f56441e48fe8284","desc":""},"expiration":{"not_valid_before":1717675210,"not_valid_after":1720094410},"additional_emails_to_notify":[]}}},"signature":"a66c2dcd58e7c123f181dc006a177c94c88cc943cf13a7148c65a11623433434cfe4dea87ca01f0bddef03c9165d93beff61a493a260102d78064804ee5a3902"}}}},{"item":{"Certificate":{"LeafV1":{"data":{"hierarchy_level":{"guard":"LEAF1"},"role":"INFRASTRUCTURE","common":{"subject":{"guard":"SUBJECT1","request_id":"473425035cb60ed3a55842d81ef4e05b","pk":"b1b91f3e645f4ae6ddcdc76fab3a8db75579bb5b875e1cd32835c1eae4412dc4","requestor_desc":{"name":null,"email":null,"phone_number":null,"orcid":null},"emails_to_notify":[]},"issuer":{"guard":"ISSUER1","issuance_id":"d464b298c7f1fcc5666c284d014b6c48","identity":{"pk":"0f1368448ab0451837549a4a3d0ed77244eabd8ec6dd612c95caa75d6f7e6d21","desc":""},"expiration":{"not_valid_before":1717675210,"not_valid_after":1720094410},"additional_emails_to_notify":[]}}},"signature":"23104c5abdfc6852cf5e71f6d835a9721dd31200de73f86de44674c61fa427d06373128574e5b3372d770484cc6e785ebeb55d451aa595720a2248ed1077bf03"}}}}]
