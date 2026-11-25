#!/bin/sh
set -eu

# The node is dedicated to MedVault ciphertext. No public bootstrap peers and
# no HTTP gateway listener. The daemon itself starts with --offline.
ipfs bootstrap rm all || true
ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001
ipfs config Addresses.Gateway /ip4/127.0.0.1/tcp/8080
