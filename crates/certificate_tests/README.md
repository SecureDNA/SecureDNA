# Certificate Tests

This crate includes tests for both our test and production certificates, as well as our test tokens.
This ensure we retain compatibility with certificates and tokens which have already been issued.
We test that we can parse all items, and that their chains can be validated back to the root certificate.
For test items with an associated key we also test that the key can be decrypted and that it matches the public key.

To test the production certificates:

    cargo test --test prod_certs

To test the test certificates:

    cargo test --test test_certs

To test the test tokens:

    cargo test --test test_tokens
