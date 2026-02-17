#!/usr/bin/env bash
set -euo pipefail

echo "▶ Generating certs..."
docker compose -f generate-indexer-certs.yml run --rm generator

echo "▶ Building and starting stack..."
docker compose up -d --build

echo "✅ Done."
