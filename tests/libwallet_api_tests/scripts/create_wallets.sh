#!/bin/bash

. ./conf.sh

function create_wallet {
    wallet_name=$1
    echo 0 | $WALLET_CLI_DIR/haven-wallet-cli  --testnet --trusted-daemon --daemon-address localhost:27750 --generate-new-wallet $WALLETS_ROOT_DIR/$wallet_name --restore-height 1 --password ""
}


create_wallet alice
create_wallet bob

#create_wallet wallet_m


