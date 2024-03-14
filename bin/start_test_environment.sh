#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -u

docker compose up -d

containers=$(docker compose ps)

if [[ "$containers" == *"exited"* ]]; then
  echo "ERROR: There is an exited container. Aborting."
  echo "$containers"
  docker compose ps
  docker compose logs
  exit 1
fi
