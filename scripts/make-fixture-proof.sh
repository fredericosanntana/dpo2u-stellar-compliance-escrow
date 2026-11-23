#!/usr/bin/env bash
# Rebuilds the fictitious snapshot input for a given escrow context, proves it
# with Caatinga and copies the result into fixtures/proofs/sanctions.
#   scripts/make-fixture-proof.sh <context-as-decimal-or-U256-debug>
set -euo pipefail
cd "$(dirname "$0")/.."
ctx="${1:?context required}"
ctx="$(echo "$ctx" | tr -dc '0-9')"
node tools/sanctions-tree/build.mjs --issued-at 1795900000 --context "$ctx"
npx ctg zk prove sanctions
mkdir -p fixtures/proofs/sanctions
cp .artifacts/zk/sanctions/{proof.json,public.json,verification_key.json} fixtures/proofs/sanctions/
echo "fixture proof updated for context $ctx"
