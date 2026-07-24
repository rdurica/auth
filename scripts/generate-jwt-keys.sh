#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_DIR="${ROOT}/keys"

mkdir -p "${KEYS_DIR}"
openssl genrsa -out "${KEYS_DIR}/jwt-private.pem" 2048
openssl rsa -in "${KEYS_DIR}/jwt-private.pem" -pubout -out "${KEYS_DIR}/jwt-public.pem"
chmod 600 "${KEYS_DIR}/jwt-private.pem"
echo "Generated ${KEYS_DIR}/jwt-private.pem and ${KEYS_DIR}/jwt-public.pem"
