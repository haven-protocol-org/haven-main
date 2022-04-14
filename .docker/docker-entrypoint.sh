#!/bin/bash
set -e

mkdir /home/haven/.haven/lmdb/ -p
mkdir /wallet -p
chown -R haven:haven /home/haven/.haven
chmod 700 /home/haven/.haven
chown -R haven:haven /wallet
chmod 700 /wallet

# Check if we already have a blockchain file or download the bootstrap
if [[ -v "${force_bootstrap}" ]] || [[ (-v  "${start_bootstrap}") && (! -f /home/haven/.haven/lmdb/data.mdb) ]]; then
     su-exec haven:haven wget https://docs.havenprotocol.org/blockchain/data.mdb -O /home/haven/.haven/lmdb/data.mdb
fi

su-exec haven:haven "$@"
