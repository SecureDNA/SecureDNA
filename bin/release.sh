#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -e

display_usage() {
  echo "Release script for SecureDNA git and GHCR releases"
  echo "Usage: $0 <rel-version>"
}

# if less than one argument supplied, display usage
if [  $# -lt 1 ]
then
  display_usage
  exit 1
fi

# check whether user had supplied -h or --help . If yes display usage
if [[ "$*" == "--help" || "$*" == "-h" ]]
then
  display_usage
  exit 0
fi

ask() {
    read -p "$1 " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

TAG=$1

function chsv_check_version() {
  # see https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
  if [[ ! $1 =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)(\.(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*))*))?(\+([0-9a-zA-Z-]+(\.[0-9a-zA-Z-]+)*))?$ ]]; then
    echo "Tag '$1' is not a valid SemVer v2 string"
    echo "We usually use the simple format 1.2.3, but others are supported as well."
    echo "For all supported versions see the documentation at https://semver.org/"
    exit 1
  fi
}

chsv_check_version "$TAG"


GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD)

echo "=== You are on branch $GIT_BRANCH ==="
if ! ask "Do you wish to continue? "
then
    exit 1
fi

echo "=== Pulling newest HEAD === "
git pull origin "$GIT_BRANCH"

GIT_SHA=$(git rev-parse --short HEAD)

IMAGES=("client" "keyserver" "hdbserver")

for image in "${IMAGES[@]}"
do
  echo "=== Processing image $image ==="
  docker pull "ghcr.io/securedna/$image:$GIT_SHA"
  docker tag "ghcr.io/securedna/$image:$GIT_SHA" "ghcr.io/securedna/$image:$TAG"
  echo "docker push ghcr.io/securedna/$image:$TAG"
done

echo "=== Publish synthclient (client is private, synthclient is public), version and latest tags ==="
docker tag "ghcr.io/securedna/client:$TAG" "ghcr.io/securedna/synthclient:$TAG"
docker tag "ghcr.io/securedna/synthclient:$TAG" "ghcr.io/securedna/synthclient:latest"
echo "docker push ghcr.io/securedna/synthclient:$TAG"
echo "docker push ghcr.io/securedna/synthclient:latest"

if ask "Do you want to git tag? "
then
  echo "=== Tagging git ==="
  git tag "$TAG" --force

  echo "=== Done, generating push command ==="
  echo "git push --tags --force"
fi
