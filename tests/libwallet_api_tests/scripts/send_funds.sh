#!/bin/bash

. ./conf.sh

function send_funds {
    local amount=$1
    local dest=$(cat "$WALLET_CLI_FOLDER/$2.address.txt")

    yes | $WALLET_CLI_FOLDER/haven-wallet-cli --wallet-file $WALLET_CLI_FOLDER/wallet_m --password "" \
        --testnet --trusted-daemon --daemon-address localhost:27750  --log-file wallet_m.log \
        --command transfer $dest $amount 
       
   
}


function seed_wallets {
    local amount=$1
    send_funds $amount alice
    send_funds $amount bob
}

seed_wallets 1
seed_wallets 2
seed_wallets 5
seed_wallets 10
seed_wallets 20
seed_wallets 50
seed_wallets 100