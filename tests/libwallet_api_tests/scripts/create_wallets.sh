#!/bin/bash

# folder where cli resides
WALLET_CLI_FOLDER=/Users/dev/workspace/crypto/haven-main/build/Darwin/bugfix_wallet-api/release/bin

function create_wallet {
    wallet_name=$1
    echo 0 | $WALLET_CLI_FOLDER/haven-wallet-cli  --testnet --trusted-daemon --daemon-address localhost:27750 --generate-new-wallet $WALLET_CLI_FOLDER/$wallet_name --restore-height 1 --password ""
}


create_wallet alice
create_wallet bob

#create_wallet wallet_m


