#!/usr/bin/env bash
# Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
# SPDX-License-Identifier: MIT OR Apache-2.0

### Only affects files at or below $PWD, so make sure you're in the right place first.
###
### Optional $1 should be one of check, add, or refresh:
###   check just checks that the headers are there.
###   add actually adds headers.
###   refresh updates the copyrights for the current year.
###
### Optional $2, if non-null, says to add *only* a copyright string, without a license.
### If a file called "$PWD/.NOLICENSE" exists, acts as if "$2" was non-null;
### this prevents accidentally forgetting to include this arg.  Note that
### you must still specify "add" or nothing will be added.

# set -x

set -euo pipefail

## ++ User-serviceable parts.
## Not all of these files are present in CI, but this way you can use this script locally as well.
ignores=(
    -ignore '**/*.yaml'
    -ignore '**/*.yml'
    -ignore '**/node_modules/**'
    -ignore '**/target_wasm/**'
    -ignore 'accessions/**'
    -ignore 'crates/wasm_bindings/**/pkg/**'
    -ignore 'crates/wasm_bindings/**/pkg_node/**'
    -ignore 'frontend/common/src/all_bindings.ts'
    -ignore 'frontend/**/dist/**'
    -ignore 'target/**'
    -ignore 'test/certs/**'
    -ignore 'test/data/**'
)

spdx_org="SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>"
sed_org="SecureDNA Stiftung \(SecureDNA Foundation\) <licensing@securedna.org>"
top="."         # We always default to $PWD.  If this ever needs to be a CLI arg, change it here.
## --

## ++ Convert the `ignores` array into something we can feed to `find` for use in refresh.
declare -a out
unstar()   { echo "$top/${1//\*\*/"*"}"; }
pruned()   { unset out; local elt
             for elt in "${ignores[@]}"; do
                 if [[ "$elt" == "-ignore" ]]; then
                     out+=('-o'); out+=('-path')
                 else
                     out+=("$(unstar "$elt")"); out+=('-prune')
                 fi
             done
           }
tofind()   { pruned; find "$1" \( \( -path "*/.git*" -prune "${out[@]}" \) \) -o -type f -print0; }
redate()   { tofind "$top" | xargs -r0 sed -r -i "s%(Copyright [0-9]{4}-)[0-9]{4}( $sed_org$)%\1$(date +%Y)\2%g"; }

## ++ Add license info.
license()  { addlicense "${ignores[@]}" -y "2021-$(date +%Y)" -c "$spdx_org" -l "MIT OR Apache-2.0" -s=only "$top"; }

## ++ Remove license info.
## Because addlicense has no "copyright-only" mode, the way we add *only* copyrights is to add copyright+license and then
## strip the license.  Note that this string is hardcoded so we *only* remove the exact license string we add, as long as it
## ends at EOL, to avoid side-effecting random code which might somehow include the substring as a string constant or something.
nolicense="$top/.NOLICENSE"
nolic-p()  { if [[ -f "$nolicense" ]]; then echo " (which it does)"; fi }
only_spdx='SPDX-License-Identifier: MIT OR Apache-2.0$'
unlicense(){ tofind "$top" | xargs -r0 sed -r -i "/$only_spdx/d"; }

## ++ Check prereqs.
if ! command -v 'addlicense' &> /dev/null; then
    echo "Error: 'addlicense' is not installed."
    echo "See https://github.com/google/addlicense"
  exit 1
fi

## ++ Argument processing.
action='--check'
if (( $# > 0 )); then action="$1"; fi

only_copyright="${2:-}"
if [[ -f "$nolicense" ]]; then only_copyright='y'; fi

## ++ Actually do some work.
case "$action" in
    --check)
        addlicense "${ignores[@]}" -check "$top" | sort
        ;;
    --add)
        license;
        if [[ -n "$only_copyright" ]]; then unlicense; fi
        ;;
    --refresh)
        redate "$top"
        ;;
    *)
        echo "$0: Unknown argument: $1"; echo
        echo "Usage: mode only-copyright"; echo
        echo " mode:"
        echo "  --check:   Check for missing license headers."
        echo "  --add:     Add license headers to files without them."
        echo "  --refresh:  Update copyrights for the current year."
        echo "  With no arguments, runs --check."
        echo ""
        echo " only-copyright, or if $nolicense exists$(nolic-p):"
        echo "  Only add a copyright and strip existing license."
        exit 1
        ;;
esac
