#!/bin/bash

. ./conf.sh


rlwrap $WALLET_CLI_DIR/haven-wallet-cli --wallet-file $WALLETS_ROOT_DIR/wallet_m --password "" --testnet --trusted-daemon --daemon-address 127.0.0.1:27750  --log-file wallet_m.log

