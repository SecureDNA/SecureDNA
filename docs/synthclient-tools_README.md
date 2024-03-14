<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `synthclient-tools` docker image

`synthclient-tools`is a package for managing certs and tokens needed for running synthclient. Generally we suggest installing via package manager like `yum` or `apt`. However, `synthclient-tools` may not be able to run on such systems if certain dependencies are outdated, such as `glibc` or `openssl`.

If using a package manager is inconvenient, you may instead run our `synthclient-tools` docker image.  The instructions below parallel those in the [quickstart](https://pages.securedna.org/production/assets/Synthclient-quickstart.pdf):

## Requesting a certificate

This is the first step of the process:

```bash
docker pull ghcr.io/securedna/synthclient-tools
export OUTSIDE="$(pwd)/certs"	# Directory on real host, inside your current directory
export INSIDE="/certs"			# Directory inside the container.
mkdir -p "$OUTSIDE"

sdna() { docker run -it --volume "$OUTSIDE":"$INSIDE"/:z ghcr.io/securedna/synthclient-tools "$@"; }

## Create a certificate request.  Visit https://securedna.org/start/ to upload the result to SecureDNA.
sdna ./sdna-create-cert manufacturer leaf \
  --output "$INSIDE/companyname-leaf.certr" \
  --create-new-key "$INSIDE/companyname-leaf.priv" \
  --name "company name" \
  --email "some-email@companyname.com"
```

## Acquiring a certificate from SecureDNA

Once you have the `companyname-leaf.certr` file above, upload it by going to https://securedna.org/start/ and filling out the form.  See https://pages.securedna.org/production/assets/Synthclient-quickstart.pdf for details.

A human will review your request for reasonability. This aim is to prevent thousands of spurious certificates being automatically issued to a botnet and similar scenarios. If your message is sent from an address different from the email embedded in the certificate, we may confirm the email in the certificate to guard against typos before taking action on the certificate request.

We will reply via email with an attached certificate named `companyname-leaf.cert`, e.g., your original name, minus the `r`. 

You cannot proceed past this point until you have a .cert file to use to create a token.

## Creating a token to authorize your use of SecureDNA

The following steps can take place without any further interaction with SecureDNA  They use the `.cert` file you received from SecureDNA after submitting your certificate request.  See https://pages.securedna.org/production/assets/Synthclient-quickstart.pdf for details.

```bash
docker pull ghcr.io/securedna/synthclient-tools
export OUTSIDE="$(pwd)/certs"	# Directory on real host, inside your current directory
export INSIDE="/certs"			# Directory inside the container.
mkdir -p "$OUTSIDE"

sdna() { docker run -it --volume "$OUTSIDE":"$INSIDE"/:z ghcr.io/securedna/synthclient-tools "$@"; }

## Create a token request.  Remember to fill in the appropriate values for your company and your usage.
sdna ./sdna-create-token \
  --output "$INSIDE/token.str" \
  --create-new-key "$INSIDE/token.priv" \
  synthesizer \
  --domain "yourcompany.com" \
  --model "DNA Maker 1000" \
  --serial "DM-1234" \
  --rate-limit "10000"

# Sign the token request, to create a token.  This uses the .cert file you received from SecureDNA.
sdna ./sdna-sign-token \
  synthesizer \
  "$INSIDE/token.str" \
  "$INSIDE/companyname-leaf.cert" \
  --output "$INSIDE/token.st" \
  --days-valid "7304"
```

## Using the token you have generated

Now you can run `synthclient`:

```bash
# Run synthclient
docker run --name synthclient \
  --env SECUREDNA_SYNTHCLIENT_TOKEN_FILE="$INSIDE/token.st" \
  --env SECUREDNA_SYNTHCLIENT_KEYPAIR_FILE="$INSIDE/token.priv" \
  --env SECUREDNA_SYNTHCLIENT_KEYPAIR_PASSPHRASE_FILE="$INSIDE/token.passphrase" \
  --volume "$OUTSIDE":"$INSIDE"/:z \
  --detach \
  -p 80:80 \
  ghcr.io/securedna/synthclient-tools \
  ./synthclient
```

Note that while these commands will allow you to execute specific steps, you should still refer to the [synthclient quickstart](https://pages.securedna.org/production/assets/Synthclient-quickstart.pdf) for more information on why and when you should run each step. For example, you will need to correspond with SecureDNA before moving between the `Generate certificate request` and `Create token request` steps.
