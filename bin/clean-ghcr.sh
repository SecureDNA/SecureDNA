#!/bin/bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

# Script to delete unneeded "package" versions from GHCR.
#
# In GHCR, a package is equivalent to an image, for docker purposes.
#
# This script will help you delete package versions which end up being cruft and noise.
# We keep versions which are semver tagged, as well as those which are younger than a cutoff
# date (which you provide as an arg).
#
# To use
# - log into github through the gh helper cli https://cli.github.com/ (see below for notes on scopes)
# - source this file
# - run `delete-package-versions-dry-run <package-name> <cutoff-date>`. Cutoff date tested with "YYYY-MM-DD" format.
# - run `delete-package-versions <package-name> <cutoff-date>`
#
# Token scopes
#
# When creating a token (tested with PAT classic) for logging in w/ GH, you'll need to make sure to have
# `delete:packages` and `read:packages` token scope. If you are also responsible for tagging releases, it would also be
# convenient to have `write:packages` on this token.
#
# If you're just logging in with the web-based flow, I think it's enough if your user has these permissions (but this is untested)
#
# Also, this script has only been tested after `cd` into the repo.

fetch-package-versions() {
    gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    --paginate \
    "/orgs/securedna/packages/container/$1/versions"
}

# hacky semver check, just checks if there's a '.'
# Takes the package name and a cutoff date (removes versions older than that date)
fetch-and-filter-package-versions() {
    fetch-package-versions "$1" \
    | jq --arg CUTOFF_DATE "$2" '.[] | select((.metadata.container.tags | all(contains(".") | not)) and .created_at < $CUTOFF_DATE)'
}

fetch-and-filter-package-versions-id() {
    fetch-and-filter-package-versions "$1" "$2" \
    | jq '.id'
}

# Takes the package name and a cutoff date (removes versions before that date)
# Prints a dry run of all the id, created_at, and tags to be deleted.
delete-package-versions-dry-run() {
    fetch-and-filter-package-versions "$1" "$2" \
    | jq --compact-output '{id, created_at, tags: .metadata.container.tags}'
}

# Takes the package name and a cutoff date
# Returns packages which are both older than cutoff date and are "commit" labeled.
# This way, we always preserve younger commit labels (in case of wanting to rollback ie. for dev),
# and we also always preserve semver-tagged versions
delete-package-versions() {
    fetch-and-filter-package-versions-id "$1" "$2" \
    | xargs -d '\n' -I{} gh api \
    --method DELETE \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "/orgs/securedna/packages/container/$1/versions/{}"
}
