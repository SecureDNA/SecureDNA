#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

set -u

display_usage() {
	echo "Convenience script to convert simple FASTA string into synthclient input JSON"
	echo "Usage: $0 <fasta>"
}

# if less than one argument supplied, display usage
if [ $# -lt 1 ]; then
	display_usage
	exit 1
fi

# check whether user had supplied -h or --help . If yes display usage
if [[ "$*" == "--help" || "$*" == "-h" ]]; then
	display_usage
	exit 0
fi

jq -n --arg fasta "$1" '{fasta: $fasta}'
