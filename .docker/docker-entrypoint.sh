#!/bin/bash
set -e

mkdir /home/haven/.haven/lmdb/ -p
# Check if we already have a blockchain file or download the bootstrap
if [[ -n "${bootstrap}" ]]; then
    wget https://docs.havenprotocol.org/blockchain/data.mdb -O /home/haven/.haven/lmdb/data.mdb
fi
su-exec haven:haven "$@"