#!/bin/bash

. ./conf.sh

rlwrap $WALLET_CLI_FOLDER/haven-wallet-cli --wallet-file $WALLET_CLI_FOLDER/wallet_m --password "" --testnet --trusted-daemon --daemon-address localhost:27750  --log-file wallet_m.log start_mining

