#!/bin/sh
set -eu

# --- Core ---
export COIN=Avian
export NET=mainnet
# Credentials stay out of the repo: put the real URL in an untracked
# run-electrumx.env beside this script, or export DAEMON_URL before running.
if [ -f ./run-electrumx.env ]; then
    . ./run-electrumx.env
fi
export DAEMON_URL="${DAEMON_URL:-http://rpcuser:rpcpassword@127.0.0.1:8767/}"

# fresh DB path (leave the old one as a backup)
export DB_DIRECTORY="/home/electrumx/.electrumx/db3"

# memory cap for ElectrumX caches
export CACHE_MB=256

# --- Endpoints (bind all interfaces for client traffic; RPC is localhost only) ---
export SERVICES="ssl://0.0.0.0:50002,tcp://0.0.0.0:50001,wss://0.0.0.0:50003,rpc://127.0.0.1:8000"

# --- TLS for electrum-us.avn.network (full chain!) ---
export SSL_CERTFILE="/etc/electrumx_cert/fullchain.pem"
export SSL_KEYFILE="/etc/electrumx_cert/privkey.pem"

# --- Advertise YOUR server (not peers) ---
export REPORT_SERVICES="ssl://electrum-us.avn.network:50002,tcp://electrum-us.avn.network:50001,wss://electrum-us.avn.network:50003"

# --- Seed OTHER servers only; enable gossip ---
export PEERS="ssl://electrum-ca.avn.network:50002 ssl://electrum-eu.avn.network:50002"
export PEER_DISCOVERY=on

# --- Misc ---
export BANNER_FILE="/home/electrumx/.electrumx/banner"
unset COST_SOFT_LIMIT 2>/dev/null || true
unset COST_HARD_LIMIT 2>/dev/null || true

exec ./electrumx_server
