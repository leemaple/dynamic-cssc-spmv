#!/usr/bin/env bash
set -euo pipefail

OWNER="${GITHUB_OWNER:-leemaple}"
REPO="${GITHUB_REPO:-dynamic-cssc-spmv}"
VISIBILITY="${GITHUB_VISIBILITY:-private}"
FULL_NAME="$OWNER/$REPO"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required. On macOS: brew install gh" >&2
  exit 2
fi

gh auth status

if ! gh repo view "$FULL_NAME" >/dev/null 2>&1; then
  gh repo create "$FULL_NAME" --"$VISIBILITY" \
    --description "Dynamic CSSC maintenance for mutable ciphertext-ciphertext SpMV" \
    --disable-wiki
fi

REMOTE_URL="https://github.com/$FULL_NAME.git"
if git remote get-url origin >/dev/null 2>&1; then
  git remote set-url origin "$REMOTE_URL"
else
  git remote add origin "$REMOTE_URL"
fi

git push -u origin main

echo "Repository published: https://github.com/$FULL_NAME"
echo "The push triggers CI. To start P0a manually:"
echo "  gh workflow run p0a-rotation-probe.yml --repo $FULL_NAME"
