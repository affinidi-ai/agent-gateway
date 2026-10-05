#!/bin/bash
# Generate a test mTLS cert bundle for exercising both pinned and CA-trust
# modes against the Agent Gateway, plus the FromMtls managed-identity path.
#
# Outputs (written to $OUT_DIR, default ./envs/mtls-test-certs):
#   ca.cert.pem        / ca.key.pem        — self-signed CA (kind=ca)
#   client-ca.cert.pem / client-ca.key.pem — leaf signed by the CA above
#                                            (CN=demo-client, SAN DNS=demo-client.fabric-demo.local,
#                                             SAN URI=spiffe://fabric-demo/demo-client, EKU=clientAuth)
#   client-pinned.cert.pem / client-pinned.key.pem
#                                          — self-signed leaf, intended for pinned trust
#
# Usage:
#   ./scripts/certs/generate-mtls-test-certs.sh [output_dir]
#
# After generation, register the certs in the gateway dashboard (Secrets →
# Certificates) with the indicated `kind`:
#   ca.cert.pem            → kind=ca
#   client-pinned.cert.pem → kind=client_leaf  (use as pinned trust entry)
#
# Private keys never leave this directory and are only needed by clients
# (curl --cert/--key, Python requests cert=(…), etc).

set -euo pipefail

OUT_DIR="${1:-./envs/mtls-test-certs}"
DAYS_CA=1825
DAYS_LEAF=825

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl not found in PATH" >&2
  exit 1
fi

# ── 1. Self-signed CA ────────────────────────────────────────────────────────
cat > ca.cnf <<'EOF'
[req]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[dn]
CN = Fabric Demo Test CA
O  = Affinidi Trust Fabric (TEST ONLY)
C  = US

[v3_ca]
basicConstraints   = critical, CA:TRUE, pathlen:1
keyUsage           = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout ca.key.pem \
  -out    ca.cert.pem \
  -days   "$DAYS_CA" \
  -config ca.cnf

# ── 2. Client leaf signed by the CA ──────────────────────────────────────────
cat > client-ca.cnf <<'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = v3_req

[dn]
CN = demo-client
O  = Affinidi Trust Fabric (TEST ONLY)
C  = US

[v3_req]
basicConstraints   = critical, CA:FALSE
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = critical, clientAuth
subjectAltName     = @alt_names

[alt_names]
DNS.1 = demo-client.fabric-demo.local
URI.1 = spiffe://fabric-demo/demo-client
EOF

openssl genrsa -out client-ca.key.pem 2048
openssl req -new \
  -key    client-ca.key.pem \
  -out    client-ca.csr.pem \
  -config client-ca.cnf

openssl x509 -req \
  -in           client-ca.csr.pem \
  -CA           ca.cert.pem \
  -CAkey        ca.key.pem \
  -CAcreateserial \
  -days         "$DAYS_LEAF" \
  -extfile      client-ca.cnf \
  -extensions   v3_req \
  -out          client-ca.cert.pem

# ── 3. Self-signed leaf for pinned trust ─────────────────────────────────────
cat > client-pinned.cnf <<'EOF'
[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[dn]
CN = demo-client-pinned
O  = Affinidi Trust Fabric (TEST ONLY)
C  = US

[v3_req]
basicConstraints   = critical, CA:FALSE
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = critical, clientAuth
subjectAltName     = @alt_names

[alt_names]
DNS.1 = demo-client-pinned.fabric-demo.local
URI.1 = spiffe://fabric-demo/demo-client-pinned
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout client-pinned.key.pem \
  -out    client-pinned.cert.pem \
  -days   "$DAYS_LEAF" \
  -config client-pinned.cnf

# ── 4. Fingerprints for sanity / matching dashboard display ──────────────────
{
  echo "# Generated $(date -u +%FT%TZ)"
  echo "# All certs are TEST ONLY. Do NOT use in production."
  echo
  for f in ca.cert.pem client-ca.cert.pem client-pinned.cert.pem; do
    fp=$(openssl x509 -in "$f" -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g; s/.*/\L&/')
    sub=$(openssl x509 -in "$f" -noout -subject | sed 's/^subject=//')
    iss=$(openssl x509 -in "$f" -noout -issuer  | sed 's/^issuer=//')
    printf "%-26s sha256=%s\n  subject: %s\n  issuer:  %s\n\n" "$f" "$fp" "$sub" "$iss"
  done
} > FINGERPRINTS.txt

# ── 5. Machine-readable manifest for dashboards / automation ─────────────────
fp_ca=$(openssl x509 -in ca.cert.pem            -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g; s/.*/\L&/')
fp_pin=$(openssl x509 -in client-pinned.cert.pem -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g; s/.*/\L&/')
fp_ca_leaf=$(openssl x509 -in client-ca.cert.pem -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g; s/.*/\L&/')
sub_ca=$(openssl x509 -in ca.cert.pem -noout -subject | sed 's/^subject=//')
generated_at=$(date -u +%FT%TZ)

cat > manifest.json <<EOF
{
  "generated_at": "$generated_at",
  "warning": "TEST ONLY — do not use in production",
  "certificates": {
    "ca": {
      "file":             "ca.cert.pem",
      "kind":             "ca",
      "fingerprint_sha256": "$fp_ca",
      "subject_dn":       "$sub_ca"
    },
    "client_pinned": {
      "file":             "client-pinned.cert.pem",
      "kind":             "client_leaf",
      "fingerprint_sha256": "$fp_pin",
      "intended_trust":   "pinned"
    },
    "client_ca_signed": {
      "file":             "client-ca.cert.pem",
      "kind":             "client_leaf",
      "fingerprint_sha256": "$fp_ca_leaf",
      "intended_trust":   "ca",
      "expected_principal_subject_cn": "demo-client",
      "expected_principal_dns_san":    "demo-client.fabric-demo.local",
      "expected_principal_uri_san":    "spiffe://fabric-demo/demo-client"
    }
  }
}
EOF

# Clean up CSR + serial; keep .cnf for traceability.
rm -f client-ca.csr.pem ca.srl

cat <<EOF

✅  mTLS test bundle written to: $(pwd)

Files:
  ca.cert.pem              kind=ca               (register in cert store)
  ca.key.pem               PRIVATE — sign more leaves; never upload
  client-ca.cert.pem       client leaf (CA mode) — present to gateway
  client-ca.key.pem        PRIVATE — pair with client-ca.cert.pem
  client-pinned.cert.pem   kind=client_leaf      (register in cert store, pin by id)
  client-pinned.key.pem    PRIVATE — pair with client-pinned.cert.pem
  FINGERPRINTS.txt         SHA-256 fingerprints + DNs for cross-checking
  manifest.json            machine-readable bundle metadata (kinds, fingerprints, intended trust)

Quick smoke tests:

  # Pinned mode (channel: MtlsTrust=Pinned{[client-pinned-id]}, binding=fingerprint)
  curl -v --cert client-pinned.cert.pem --key client-pinned.key.pem \\
    -k https://localhost:8443/

  # CA mode (channel: MtlsTrust=Ca{[ca-id], require_eku_client_auth=true},
  #          binding=subject_cn → principal "demo-client")
  curl -v --cert client-ca.cert.pem --key client-ca.key.pem \\
    -k https://localhost:8443/

EOF
