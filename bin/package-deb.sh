#!/bin/bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# Example usage: ./package-deb.sh 1.0.5 securedna/target/release arm64
VERSION=$1
SYNTHCLIENT_TARGET_DIR=$2
ARCH=$3

# ARCH must be amd64 or arm64
if ! [[ "$ARCH" == "amd64" || "$ARCH" == "arm64" ]]
then
  echo "Please specify amd64 or arm64"
  exit 0
fi

# Set up deps for building .deb
sudo apt-get update -yqq
sudo apt-get install -y devscripts build-essential cdbs

# File structure of root directory for building .deb package out of
# $INPUT_PACKAGE_ROOT/usr/bin/<put binaries here>
# $INPUT_PACKAGE_ROOT/DEBIAN/control
echo "Setting up directories and filenames"
INPUT_PACKAGE_ROOT=.debpkg
mkdir -p $INPUT_PACKAGE_ROOT/usr/bin
mkdir -p $INPUT_PACKAGE_ROOT/DEBIAN
CONTROL="$INPUT_PACKAGE_ROOT/DEBIAN/control"
DEB_FILE="synthclient_${VERSION}_$ARCH.deb"

# Move binaries over
echo "Copying binaries"
BINARIES="synthclient sdna-sign-cert sdna-sign-token sdna-create-key sdna-create-cert sdna-create-token sdna-inspect-cert sdna-inspect-token sdna-merge-cert sdna-retrieve-cert-request"
for binary in $BINARIES; do cp -p "$SYNTHCLIENT_TARGET_DIR/$binary" "$INPUT_PACKAGE_ROOT/usr/bin"; done

# template for /DEBIAN/control
# https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-binarycontrolfiles
# For dependencies, these work on debian bookworm or later
echo "Writing control file"
{
    echo "Package: synthclient"
    echo "Version: $VERSION"
    echo "Architecture: $ARCH"
    echo "Maintainer: SecureDNA Stiftung (SecureDNA Foundation)"
    echo "Depends: libc6 (>= 2.34), libssl3 (>= 3.0.2)"
    echo "Filename: ./$DEB_FILE"
    echo "Description: SecureDNA client"
    echo " This is the client-side part of the SecureDNA synthesis screening system,"
    echo " along with related utilities.  For more information, see https://securedna.org/"
} >> $CONTROL

echo "Building .deb"
dpkg-deb -Zgzip --root-owner-group --build "$INPUT_PACKAGE_ROOT" "$DEB_FILE"

#EOF
