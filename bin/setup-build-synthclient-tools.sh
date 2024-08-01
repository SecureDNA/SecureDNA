#!/bin/bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# Example usage: ./setup-build-synthclient-tools.sh 1.0.5
VERSION=$1

# Install rust version manager
# TODO figure out a way to not have a default rust install, since it may not match rust-toolchain.toml
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# Source cargo for current shell
# shellcheck disable=SC1091
# because this is a path that will exist on remote server but maybe not locally
 . "$HOME/.cargo/env"
# Install apt build requirements
# TODO perhaps use `DEBIAN_FRONTEND=noninteractive` instead
sudo apt install -y git build-essential libssl-dev pkg-config
# Add github to known hosts so git clone doesn't fail
ssh-keyscan github.com >> "$HOME"/.ssh/known_hosts 2>/dev/null
# Clone monorepo
git clone git@github.com:securedna/securedna-dev
# navigate to monorepo
cd securedna-dev
# Checkout the correct tag for release
git checkout "$VERSION"
# Build release binaries. Have a nice cup of tea :)
cargo build --release -p synthclient -p certificate-client
