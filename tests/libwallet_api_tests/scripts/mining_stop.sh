#!/bin/bash

. ./conf.sh

rlwrap $WALLET_CLI_DIR/haven-wallet-cli --wallet-file wallet_m --password "" --testnet --trusted-daemon --daemon-address localhost:27750  --log-file wallet_miner.log stop_mining

