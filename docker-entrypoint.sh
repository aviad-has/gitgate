#!/bin/sh
set -e

CERTS_DIR=/data/certs
POLICY_FILE=/data/policy.yaml

# Generate certs on first run if they don't exist.
# Runs as root so we can write to the volume, then chowns to gitgate.
if [ ! -f "$CERTS_DIR/server.crt" ]; then
    HOSTNAME="${GITGATE_HOSTNAME:-localhost}"
    echo "[gitgate] Generating TLS certificates for hostname: $HOSTNAME"
    mkdir -p "$CERTS_DIR"
    gitgate-cert generate --out-dir "$CERTS_DIR" --hostname "$HOSTNAME"
    chown -R gitgate "$CERTS_DIR"
    echo "[gitgate] Install $CERTS_DIR/ca.crt on developer machines to trust the proxy."
fi

# Require a policy file
if [ ! -f "$POLICY_FILE" ]; then
    echo "[gitgate] ERROR: No policy file found at $POLICY_FILE"
    echo "[gitgate] Copy policy.yaml.example to $POLICY_FILE and edit it."
    exit 1
fi

# Drop from root to the gitgate user before starting the proxy.
exec su-exec gitgate gitgate-proxy \
    --bind 0.0.0.0 \
    --port "${GITGATE_PORT:-7443}" \
    --policy "$POLICY_FILE" \
    --tls-cert "$CERTS_DIR/server.crt" \
    --tls-key "$CERTS_DIR/server.key"
