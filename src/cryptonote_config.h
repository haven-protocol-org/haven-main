// Copyright (c) 2014-2022, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <array>
#include <stdexcept>
#include <string>
#include <boost/uuid/uuid.hpp>

#define CRYPTONOTE_DNS_TIMEOUT_MS                       20000

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CURRENT_TRANSACTION_VERSION                     8
#define OFFSHORE_TRANSACTION_VERSION                    3
#define POU_TRANSACTION_VERSION                         6
#define COLLATERAL_TRANSACTION_VERSION                  7
#define HAVEN_TYPES_TRANSACTION_VERSION                 8

#define CURRENT_BLOCK_MAJOR_VERSION                     1
#define CURRENT_BLOCK_MINOR_VERSION                     1
#define CRYPTONOTE_V2_POW_BLOCK_VERSION                 2
#define CRYPTONOTE_V3_POW_BLOCK_VERSION                 3
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT              60*60*2
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10

// UNLOCK TIMES
#define TX_V6_OFFSHORE_UNLOCK_BLOCKS                    21*720  // 21 day unlock time
#define TX_V6_ONSHORE_UNLOCK_BLOCKS                     360     // 12 hour unlock time
#define TX_V6_XASSET_UNLOCK_BLOCKS                      1440    // 2 day unlock time
#define TX_V7_ONSHORE_UNLOCK_BLOCKS                     21*720  // 21 day unlock time
#define TX_V7_OFFSHORE_UNLOCK_BLOCKS                    21*720  // 21 day unlock time
#define TX_V7_XASSET_UNLOCK_BLOCKS                      1440    // 2 day unlock time
#define TX_OFFSHORE_UNLOCK_BLOCKS_TESTNET               60      // 2 hour unlock time - FOR TESTING ONLY
#define TX_ONSHORE_UNLOCK_BLOCKS_TESTNET                30      // 1 hour unlock time - FOR TESTING ONLY
#define TX_XASSET_UNLOCK_BLOCKS_TESTNET                 60      // 2 hour unlock time - FOR TESTING ONLY

// HF21 Unlock times
#define HF21_COLLATERAL_LOCK_BLOCKS                     14*720  // 14 day unlock time
#define HF21_SHORING_LOCK_BLOCKS                        720     // 1 day unlock time
#define HF21_XASSET_LOCK_BLOCKS                         1440    // 2 day unlock time
#define HF21_COLLATERAL_LOCK_BLOCKS_TESTNET             30      // 1 hour unlock time - FOR TESTING ONLY
#define HF21_SHORING_LOCK_BLOCKS_TESTNET                10      // 20 minute unlock time - FOR TESTING ONLY
#define HF21_XASSET_LOCK_BLOCKS_TESTNET                 20      // 40 minute unlock time - FOR TESTING ONLY

// HF23 Unlock times
#define HF23_COLLATERAL_LOCK_BLOCKS                     720     // 1 day unlock time
#define HF23_SHORING_LOCK_BLOCKS                        720     // 1 day unlock time
#define HF23_XASSET_LOCK_BLOCKS                         1440    // 2 day unlock time
#define HF23_COLLATERAL_LOCK_BLOCKS_TESTNET             30      // 1 hour unlock time - FOR TESTING ONLY
#define HF23_SHORING_LOCK_BLOCKS_TESTNET                10      // 20 minute unlock time - FOR TESTING ONLY
#define HF23_XASSET_LOCK_BLOCKS_TESTNET                 20      // 40 minute unlock time - FOR TESTING ONLY

// HF25 Unlock times
#define HF25_AUDIT_LOCK_BLOCKS                          1440    // 2 day unlock time
#define HF25_AUDIT_LOCK_GRACE_PERIOD_BLOCKS             30      // 1 hour for the transaction to go through after being submitted

// HF27 Unlock times
#define HF27_SHORING_LOCK_BLOCKS                        10     // 20 minute unlock time
#define HF27_XASSET_LOCK_BLOCKS                         720    // 1 day unlock time
#define HF27_SHORING_LOCK_BLOCKS_TESTNET                10      // 20 minute unlock time - FOR TESTING ONLY
#define HF27_XASSET_LOCK_BLOCKS_TESTNET                 20      // 40 minute unlock time - FOR TESTING ONLY


#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               60

// MONEY_SUPPLY - total number coins to be generated
#define MONEY_SUPPLY                                    ((uint64_t)(-1))
#define EMISSION_SPEED_FACTOR_PER_MINUTE                (20)
#define FINAL_SUBSIDY_PER_MINUTE                        ((uint64_t)300000000000) // 3 * pow(10, 11)

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2    300000 //size of block (bytes) after which reward for block calculated using block size
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    300000 //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                12
// COIN - number of smallest units in one coin
#define COIN                                            ((uint64_t)1000000000000) // pow(10, 12)
#define HAVEN_MAX_TX_VALUE                              ((uint64_t)15000000000000000000ull)
#define HAVEN_MAX_TX_VALUE_TESTNET                      ((uint64_t)18000000000000000000ull)

#define FEE_PER_KB_OLD                                  ((uint64_t)10000000000) // pow(10, 10)
#define FEE_PER_KB                                      ((uint64_t)2000000000) // 2 * pow(10, 9)
#define FEE_PER_BYTE                                    ((uint64_t)300000)
#define DYNAMIC_FEE_PER_KB_BASE_FEE                     ((uint64_t)2000000000) // 2 * pow(10,9)
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000) // 10 * pow(10,12)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)2000000000 * (uint64_t)CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT         ((uint64_t)3000)

#define ORPHANED_BLOCKS_MAX_COUNT                       100

#define PRICING_RECORD_VALID_BLOCKS                     10
#define PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK       120  // seconds

#define DIFFICULTY_TARGET_V2                            120  // seconds
#define DIFFICULTY_TARGET_V1                            120  // seconds - before first fork
#define DIFFICULTY_WINDOW                               60 // blocks
#define DIFFICULTY_WINDOW_V2                            70 // blocks
#define DIFFICULTY_LAG                                  15  // !!!
#define DIFFICULTY_CUT                                  6  // timestamps to cut after sorting
#define DIFFICULTY_BLOCKS_COUNT                         DIFFICULTY_WINDOW
#define DIFFICULTY_BLOCKS_COUNT_V2                      DIFFICULTY_WINDOW_V2

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1   DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define DIFFICULTY_BLOCKS_ESTIMATE_TIMESPAN             DIFFICULTY_TARGET_V1 //just alias; used by tests


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT              25000  //max blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT_PRE_V4       100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              20     //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    86400  //seconds, one day
#define CRYPTONOTE_MEMPOOL_TX_CONVERSION_LIVETIME         3600   //seconds, one hour
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     604800 //seconds, one week


#define CRYPTONOTE_DANDELIONPP_STEMS              2 // number of outgoing stem connections per epoch
#define CRYPTONOTE_DANDELIONPP_FLUFF_PROBABILITY 20 // out of 100
#define CRYPTONOTE_DANDELIONPP_MIN_EPOCH         10 // minutes
#define CRYPTONOTE_DANDELIONPP_EPOCH_RANGE       30 // seconds
#define CRYPTONOTE_DANDELIONPP_FLUSH_AVERAGE      5 // seconds average for poisson distributed fluff flush
#define CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE   39 // seconds (see tx_pool.cpp for more info)

// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

// Both below are in seconds. The idea is to delay forwarding from i2p/tor
// to ipv4/6, such that 2+ incoming connections _could_ have sent the tx
#define CRYPTONOTE_FORWARD_DELAY_BASE (CRYPTONOTE_NOISE_MIN_DELAY + CRYPTONOTE_NOISE_DELAY_RANGE)
#define CRYPTONOTE_FORWARD_DELAY_AVERAGE (CRYPTONOTE_FORWARD_DELAY_BASE + (CRYPTONOTE_FORWARD_DELAY_BASE / 2))

#define CRYPTONOTE_MAX_FRAGMENTS                        20 // ~20 * NOISE_BYTES max payload size for covert/noise send

#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_BLOCK_COUNT     1000
#define COMMAND_RPC_GET_BLOCKS_FAST_MAX_TX_COUNT        20000
#define MAX_RPC_CONTENT_LENGTH                          1048576 // 1 MB

#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT                   12
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_MAX_PEERS_IN_HANDSHAKE                      250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       2048       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     8192       // kB/s

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define RPC_IP_FAILS_BEFORE_BLOCK                       3

#define CRYPTONOTE_NAME                         "haven"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define RPC_PAYMENTS_DATA_FILENAME              "rpcpayments.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_MIN_MIXIN_4                  1
#define HF_VERSION_MIN_MIXIN_6                  1
#define HF_VERSION_MIN_MIXIN_10                 5
#define HF_2_MIN_MIXIN_9                        2
#define HF_VERSION_ENFORCE_RCT                  5
#define HF_VERSION_PER_BYTE_FEE                 5
#define HF_VERSION_SMALLER_BP                   5
#define HF_VERSION_DYNAMIC_FEE                  11
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       11
#define HF_VERSION_MIN_2_OUTPUTS                12
#define HF_VERSION_MIN_V2_COINBASE_TX           12
#define HF_VERSION_SAME_MIXIN                   12
#define HF_VERSION_REJECT_SIGS_IN_COINBASE      12
#define HF_VERSION_ENFORCE_MIN_AGE              12
#define HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY 12
#define HF_VERSION_CLSAG                        13

// Haven-specific HF definitions
#define HF_11_MIN_MIXIN_10                      11
#define HF_VERSION_OFFSHORE_PRICING             11
#define HF_VERSION_OFFSHORE_FULL                13
#define HF_VERSION_OFFSHORE_FEES_V2             14
#define HF_VERSION_XASSET_FULL                  16
#define HF_VERSION_XASSET_FEES_V2               17
#define HF_VERSION_HAVEN2                       18
#define HF_PER_OUTPUT_UNLOCK_VERSION            19
#define HF_VERSION_USE_COLLATERAL               20

// Post-v0.18-rebase - Haven v3.2
#define HF_VERSION_USE_CONVERSION_RATE          21
#define HF_VERSION_USE_HAVEN_TYPES              21
#define HF_VERSION_CONVERSION_FEES_IN_XHV       21
#define HF_VERSION_USE_COLLATERAL_V2            21
#define HF_VERSION_MIN_MIXIN_15                 21
#define HF_VERSION_EXACT_COINBASE               21
#define HF_VERSION_DETERMINISTIC_UNLOCK_TIME    21
#define HF_VERSION_BULLETPROOF_PLUS             21
#define HF_VERSION_VIEW_TAGS                    21
#define HF_VERSION_2021_SCALING                 21

// Haven v3.3 definitions
#define HF_VERSION_USE_CHECKPOINTS              22
#define HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS 22

// Haven v4.0 definitions
#define HF_VERSION_SLIPPAGE                     23
#define HF_VERSION_YIELD                        23
#define HF_VERSION_CONVERSION_FEES_NOT_BURNT    23

// Haven v4.1 definitions
#define HF_VERSION_SLIPPAGE_V2                  24
#define HF_VERSION_BURN                         24
#define HF_VERSION_CONVERSION_FEES_NOT_BURNT_FINAL    24
#define HF_VERSION_OFFSHORE_FEES_V3             24
#define HF_VERSION_MAX_CONV_TRANSACTION_FEE          24
#define MAX_CONV_TRANSACTION_FEE                   ((uint64_t)10000000000000ull)

// Haven v4.2 definitions
#define HF_VERSION_SUPPLY_AUDIT                 25
#define SUPPLY_AUDIT_BLOCK_HEIGHT               ((uint64_t)1713000)
#define OLD_OUTPUT_LOCK_BLOCK_AFTER_AUDIT       ((uint64_t)20000000)  //After the supply audit ends, all old outputs will be locked to this block, to avoid spending them


#define HF_VERSION_SUPPLY_AUDIT_END             26
#define HF_VERSION_VBS_DISABLING                  27


#define STAGENET_VERSION                        0x0e
#define TESTNET_VERSION                         0x1b

#define OFFSHORE_PRICING_BLOCKS_TO_AVERAGE      30

#define BURNT_CONVERSION_FEES_MINT_AMOUNT       ((uint64_t)2580000000000000000ull)
#define BURNT_CONVERSION_FEES_MINT_HEIGHT       ((uint64_t)1656720)

#define BURNT_CONVERSION_FEES_MINT_AMOUNT_FINAL       ((uint64_t)511812000000000000ull)
#define BURNT_CONVERSION_FEES_MINT_HEIGHT_FINAL       ((uint64_t)1692780)

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8
#define CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES 2

#define HASH_OF_HASHES_STEP                     512

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16
#define BULLETPROOF_PLUS_MAX_OUTPUTS            16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500 // the smaller, the more space saved

#define RPC_CREDITS_PER_HASH_SCALE ((float)(1<<24))

#define DNS_BLOCKLIST_LIFETIME (86400 * 8)

//The limit is enough for the mandatory transaction content with 16 outputs (547 bytes),
//a custom tag (1 byte) and up to 32 bytes of custom data for each recipient.
// (1+32) + (1+1+16*32) + (1+16*32) = 1060
#define MAX_TX_EXTRA_SIZE                       1060

// New constants are intended to go here
namespace config
{
  uint64_t const DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  uint8_t const FEE_CALCULATION_MAX_RETRIES = 10;
  uint64_t const DEFAULT_DUST_THRESHOLD = ((uint64_t)2000000000); // 2 * pow(10, 9)
  uint64_t const BASE_REWARD_CLAMP_THRESHOLD = ((uint64_t)100000000); // pow(10, 8)

  uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x5af4; //hvx
  uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0xcd774; //hvi
  uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x12d974; //hvs
  uint16_t const P2P_DEFAULT_PORT = 17749;
  uint16_t const RPC_DEFAULT_PORT = 17750;
  uint16_t const ZMQ_RPC_DEFAULT_PORT = 17751;
  boost::uuids::uuid const NETWORK_ID = { {
      0x05 ,0x39, 0xF1, 0x70 , 0x61, 0x04 , 0x41, 0x60, 0x17, 0x32, 0x00, 0x81, 0x16, 0xA1, 0xA1, 0x10
    } };
  std::string const GENESIS_TX = "023c01ff0001ffffffffffff07020bf6522f9152fa26cd1fc5c022b1a9e13dab697f3acf4b4d0ca6950a867a194321011d92826d0656958865a035264725799f39f6988faa97d532f972895de849496d00";
  uint32_t const GENESIS_NONCE = 10000;

  // Hash domain separators
  const char HASH_KEY_BULLETPROOF_EXPONENT[] = "bulletproof";
  const char HASH_KEY_BULLETPROOF_PLUS_EXPONENT[] = "bulletproof_plus";
  const char HASH_KEY_BULLETPROOF_PLUS_TRANSCRIPT[] = "bulletproof_plus_transcript";
  const char HASH_KEY_RINGDB[] = "ringdsb";
  const char HASH_KEY_SUBADDRESS[] = "SubAddr";
  const unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  const unsigned char HASH_KEY_WALLET = 0x8c;
  const unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  const unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x58;
  const unsigned char HASH_KEY_MEMORY = 'k';
  const unsigned char HASH_KEY_MULTISIG[] = {'M', 'u', 'l', 't' , 'i', 's', 'i', 'g', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const unsigned char HASH_KEY_MULTISIG_KEY_AGGREGATION[] = "Multisig_key_agg";
  const unsigned char HASH_KEY_CLSAG_ROUND_MULTISIG[] = "CLSAG_round_ms_merge_factor";
  const unsigned char HASH_KEY_TXPROOF_V2[] = "TXPROOF_V2";
  const unsigned char HASH_KEY_CLSAG_ROUND[] = "CLSAG_round";
  const unsigned char HASH_KEY_CLSAG_AGG_0[] = "CLSAG_agg_0";
  const unsigned char HASH_KEY_CLSAG_AGG_1[] = "CLSAG_agg_1";
  const char HASH_KEY_MESSAGE_SIGNING[] = "MoneroMessageSignature";
  const unsigned char HASH_KEY_MM_SLOT = 'm';
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS_SEED[] = "multisig_tx_privkeys_seed";
  const constexpr char HASH_KEY_MULTISIG_TX_PRIVKEYS[] = "multisig_tx_privkeys";
  const constexpr char HASH_KEY_TXHASH_AND_MIXRING[] = "txhash_and_mixring";
  const unsigned char HASH_KEY_AMOUNTPROOF[] = "AmountProof";

  // Multisig
  const uint32_t MULTISIG_MAX_SIGNERS{16};

  std::string const GOVERNANCE_WALLET_ADDRESS = "hvxy7YfeE8SdTrCmSqLB59WoQn3ZQun1aLX36X3eb1R7Fb26VuNpc235q4fguGUxfGKerywFPnweu15S8RB8DzTJ8Q4hGJCgvv";
  std::string const GOVERNANCE_WALLET_ADDRESS_MULTI = "hvxy3f2PhAhimkeLf617BsbVn6UTbofVcMzofXGsSNLoMFr2SrSxRJ9f52Am1QLVddKetXPKHoTLbBaLNT1kMU6Q3kYRc3t6pF";
  std::string const GOVERNANCE_WALLET_ADDRESS_MULTI_NEW = "hvxyAvVZaz19FzURQfXHHpVqoJF7baXVm4A6FvqFm7wq95vveSitDGWWaxdxR5MFW6BPJDBgkYjp9aUuYurQWZHx2pL5jPTXgH";
  std::string const GOVERNANCE_WALLET_ADDRESS_MULTI_V23 = "hvxy6k7fN9k1cG8N5iabCu5Ts6pJ5E9fGDb9qw1b8zEvJECN5tAewry3TjKR3AqinZT9eDDYnXLVN1FZ65cQVAjq2BoBrRDErR";
  
  std::array<std::string, 3> const ORACLE_URLS = {{"oracle.havenprotocol.org:443", "oracle2.havenprotocol.org:443", "oracle3.havenprotocol.org:443"}};
  std::string const ORACLE_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5YBxWx1AZCA9jTUk8Pr2uZ9jpfRt\n"
    "KWv3Vo1/Gny+1vfaxsXhBQiG1KlHkafNGarzoL0WHW4ocqaaqF5iv8i35A==\n"
    "-----END PUBLIC KEY-----\n";

  namespace testnet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x59f4; //hvt
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x499f4; //hvti
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x919f4; //hvts
    uint16_t const P2P_DEFAULT_PORT = 27749;
    uint16_t const RPC_DEFAULT_PORT = 27750;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 27751;
    boost::uuids::uuid const NETWORK_ID = { {
        0x05 ,0x39, 0xF1, 0x70 , 0x61, 0x04 , 0x41, 0x60, 0x17, 0x32, 0x00, 0x81, 0x16, 0xA1, TESTNET_VERSION, 0x11
      } };
    std::string const GENESIS_TX = "023c01ff0001ffffffffffff07020bf6522f9152fa26cd1fc5c022b1a9e13dab697f3acf4b4d0ca6950a867a194321011d92826d0656958865a035264725799f39f6988faa97d532f972895de849496d00";
    // 15M premine
    //std::string const GENESIS_TX = "023c01ff00018080f0f6ec90ad95d00102d12e955cf07c7569e9678afeb9c879c04f5e5850987c83feaea7afdb462b8f832101f352146306f0d841fed393dda5ad977cb009430442394c72f1fae952af0bb24700";
    // 18.4M premine
    //std::string const GENESIS_TX = "023c01ff00018cffffffffffffffff0102fa999deaf77e7666b1ce36a81107ee39ad51cd70eb5f99d3ce9d0afc40fb4ac821016f8a067f6f8b2988fa71c665f05521616f309a49b345af21633718507b73e83a00";
    uint32_t const GENESIS_NONCE = 10001;

    std::string const GOVERNANCE_WALLET_ADDRESS = "hvta9gEeEpp8tWm4DK3gzZH5dsoAkbtwBL19EGnaYjApRoo8bXQg2GJPjBiji6NMbLDUUkfZw9Q4sh558r37Ucjb9ZHaDUns8N";
    std::string const GOVERNANCE_WALLET_ADDRESS_MULTI = "hvta9gEeEpp8tWm4DK3gzZH5dsoAkbtwBL19EGnaYjApRoo8bXQg2GJPjBiji6NMbLDUUkfZw9Q4sh558r37Ucjb9ZHaDUns8N";

    std::array<std::string, 3> const ORACLE_URLS = {{"oracle-testnet.havenprotocol.org:443", "oracle-testnet.havenprotocol.org:443", "oracle-testnet.havenprotocol.org:443"}};
    std::string const ORACLE_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtWqvQh7OdXrdgXcDeBMRVfLWTW3F\n"
      "wByeoVJFBfZymScJIJl46j66xG6ngnyj4ai4/QPFnSZ1I9jjMRlTWC4EPA==\n"
      "-----END PUBLIC KEY-----\n";
  }

  namespace stagenet
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 0x239974; //hvsa
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 0x279974; //hvsi
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 0x2c1974; //hvss
    uint16_t const P2P_DEFAULT_PORT = 37749;
    uint16_t const RPC_DEFAULT_PORT = 37750;
    uint16_t const ZMQ_RPC_DEFAULT_PORT = 37751;
    boost::uuids::uuid const NETWORK_ID = { {
        0x05 ,0x39, 0xF1, 0x70 , 0x61, 0x04 , 0x41, 0x60, 0x17, 0x32, 0x00, 0x81, 0x16, 0xA1, STAGENET_VERSION, 0x12
      } };
    std::string const GENESIS_TX = "023c01ff0001ffffffffffff07020bf6522f9152fa26cd1fc5c022b1a9e13dab697f3acf4b4d0ca6950a867a194321011d92826d0656958865a035264725799f39f6988faa97d532f972895de849496d00";
    //std::string const GENESIS_TX = "013c01ff0001ffffffffffff0f029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd0880712101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b";

    std::string const GOVERNANCE_WALLET_ADDRESS = "hvsaeLCg4ZkjLRQf8ciYSjHFX8y2CmrnibNBRDZiyyANTFtXQbxHy5PFD79MvmB9mtHeX8XLa36BJ33QoEDh8PH8hULLZnpdNx7";
    std::string const GOVERNANCE_WALLET_ADDRESS_MULTI = "hvsaeLCg4ZkjLRQf8ciYSjHFX8y2CmrnibNBRDZiyyANTFtXQbxHy5PFD79MvmB9mtHeX8XLa36BJ33QoEDh8PH8hULLZnpdNx7";
    uint32_t const GENESIS_NONCE = 10002;

    std::array<std::string, 3> const ORACLE_URLS = {{"oracle-stagenet.havenprotocol.org:443", "oracle-stagenet.havenprotocol.org:443", "oracle-stagenet.havenprotocol.org:443"}};
    std::string const ORACLE_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEtWqvQh7OdXrdgXcDeBMRVfLWTW3F\n"
      "wByeoVJFBfZymScJIJl46j66xG6ngnyj4ai4/QPFnSZ1I9jjMRlTWC4EPA==\n"
      "-----END PUBLIC KEY-----\n";
  }
}

namespace cryptonote
{
  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    STAGENET,
    FAKECHAIN,
    UNDEFINED = 255
  };
  struct config_t
  {
    uint64_t const CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t const CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t const P2P_DEFAULT_PORT;
    uint16_t const RPC_DEFAULT_PORT;
    uint16_t const ZMQ_RPC_DEFAULT_PORT;
    boost::uuids::uuid const NETWORK_ID;
    std::string const GENESIS_TX;
    uint32_t const GENESIS_NONCE;
    std::array<std::string, 3> const ORACLE_URLS;
    std::string const ORACLE_PUBLIC_KEY;
  };
  inline const config_t& get_config(network_type nettype)
  {
    static const config_t mainnet = {
      ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::P2P_DEFAULT_PORT,
      ::config::RPC_DEFAULT_PORT,
      ::config::ZMQ_RPC_DEFAULT_PORT,
      ::config::NETWORK_ID,
      ::config::GENESIS_TX,
      ::config::GENESIS_NONCE,
      ::config::ORACLE_URLS,
      ::config::ORACLE_PUBLIC_KEY
    };
    static const config_t testnet = {
      ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::testnet::P2P_DEFAULT_PORT,
      ::config::testnet::RPC_DEFAULT_PORT,
      ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
      ::config::testnet::NETWORK_ID,
      ::config::testnet::GENESIS_TX,
      ::config::testnet::GENESIS_NONCE,
      ::config::testnet::ORACLE_URLS,
      ::config::testnet::ORACLE_PUBLIC_KEY
    };
    static const config_t stagenet = {
      ::config::stagenet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
      ::config::stagenet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
      ::config::stagenet::P2P_DEFAULT_PORT,
      ::config::stagenet::RPC_DEFAULT_PORT,
      ::config::stagenet::ZMQ_RPC_DEFAULT_PORT,
      ::config::stagenet::NETWORK_ID,
      ::config::stagenet::GENESIS_TX,
      ::config::stagenet::GENESIS_NONCE,
      ::config::stagenet::ORACLE_URLS,
      ::config::stagenet::ORACLE_PUBLIC_KEY
    };
    switch (nettype)
    {
      case MAINNET: return mainnet;
      case TESTNET: return testnet;
      case STAGENET: return stagenet;
      case FAKECHAIN: return mainnet;
      default: throw std::runtime_error("Invalid network type");
    }
  };
}
