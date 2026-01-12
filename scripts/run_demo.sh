#!/usr/bin/env bash
set -euo pipefail
python -m hybrilink.gen_keys --outdir keys
python -m hybrilink.server --host 127.0.0.1 --port 9000 --server-ed25519 keys/server_ed25519.pem &
SRV_PID=$!
sleep 0.5
python -m hybrilink.client --host 127.0.0.1 --port 9000 --server-ed25519-pub keys/server_ed25519_pub.pem --message "hello hybrilink"
kill $SRV_PID
