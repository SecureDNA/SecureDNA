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
    --notify <EMAIL>                            Email(s) to be notified when an ELT issued by this cert is used (optional, only for leaf certs).
                                                Provide one email address per use, e.g. "--notify a@example.com --notify b@example.com".
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
        Public key of the audit recipient (optional). Expects a hex encoded secp256k1 pubic key

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
    --notify <EMAIL>            Email(s) to be notified when an ELT issued by this cert is used (optional, only for leaf certs)     
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
