// Copyright (c) 2014-2022, The Monero Project
// Portions Copyright (c) 2019-2023, Haven Protocol
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

#include <unordered_set>
#include <random>
#include "include_base_utils.h"
#include "string_tools.h"
using namespace epee;

#include "common/apply_permutation.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_basic/tx_extra.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "offshore/asset_types.h"

#include <boost/multiprecision/cpp_bin_float.hpp>

using namespace crypto;

namespace cryptonote
{
  //---------------------------------------------------------------
  void classify_addresses(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr, size_t &num_stdaddresses, size_t &num_subaddresses, account_public_address &single_dest_subaddress)
  {
    num_stdaddresses = 0;
    num_subaddresses = 0;
    std::unordered_set<cryptonote::account_public_address> unique_dst_addresses;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      if (change_addr && dst_entr.addr == change_addr)
        continue;
      if (unique_dst_addresses.count(dst_entr.addr) == 0)
      {
        unique_dst_addresses.insert(dst_entr.addr);
        if (dst_entr.is_subaddress)
        {
          ++num_subaddresses;
          single_dest_subaddress = dst_entr.addr;
        }
        else
        {
          ++num_stdaddresses;
        }
      }
    }
    LOG_PRINT_L2("destinations include " << num_stdaddresses << " standard addresses and " << num_subaddresses << " subaddresses");
  }
  //---------------------------------------------------------------
  bool get_deterministic_output_key(const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key, crypto::view_tag &view_tag)
  {

    crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);
    bool r = crypto::generate_key_derivation(address.m_view_public_key, tx_key.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << address.m_view_public_key << ", " << tx_key.sec << ")");

    r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, output_key);
    CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key(" << derivation << ", "<< address.m_spend_public_key << ")");

    crypto::derive_view_tag(derivation, output_index, view_tag);
    
    return true;
  }
  //---------------------------------------------------------------
  // Governance code credit to Loki project https://github.com/loki-project/loki
  keypair get_deterministic_keypair_from_height(uint64_t height)
  {
    keypair k;

    ec_scalar& sec = k.sec;

    for (int i=0; i < 8; i++)
    {
      uint64_t height_byte = height & ((uint64_t)0xFF << (i*8));
      uint8_t byte = height_byte >> i*8;
      sec.data[i] = byte;
    }
    for (int i=8; i < 32; i++)
    {
      sec.data[i] = 0x00;
    }

    generate_keys(k.pub, k.sec, k.sec, true);

    return k;
  }
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, std::map<std::string, uint64_t> fee_map,  std::map<std::string, uint64_t> offshore_fee_map, std::map<std::string, uint64_t> xasset_fee_map, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs, uint8_t hard_fork_version, cryptonote::network_type nettype) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();
    tx.output_unlock_times.clear();

    keypair txkey = keypair::generate(hw::get_device("default"));
    add_tx_pub_key_to_extra(tx, txkey.pub);
    if(!extra_nonce.empty())
      if(!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
        return false;
    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    keypair gov_key = get_deterministic_keypair_from_height(height);

    txin_gen in;
    in.height = height;

    uint64_t block_reward;
    if(!get_block_reward(median_weight, current_block_weight, already_generated_coins, block_reward, hard_fork_version))
    {
      LOG_PRINT_L0("Block is too big");
      return false;
    }

#if defined(DEBUG_CREATE_BLOCK_TEMPLATE)
    // NEAC: need to iterate over the currency maps to output all fees
    LOG_PRINT_L1("Creating block template: block reward " << block_reward);
    for (const auto &fee: fee_map) {
      LOG_PRINT_L1("\t" << fee.first << " fee " << fee);
    }
#endif

    uint64_t governance_reward = 0;
    if (hard_fork_version >= 3) {
      if (already_generated_coins != 0)
      {
        governance_reward = get_governance_reward(height, block_reward);
        block_reward -= governance_reward;
      }
    }

    block_reward += fee_map["XHV"];
    uint64_t summary_amounts = 0;
    crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);;
    crypto::public_key out_eph_public_key = AUTO_VAL_INIT(out_eph_public_key);
    bool r = crypto::generate_key_derivation(miner_address.m_view_public_key, txkey.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to generate_key_derivation(" << miner_address.m_view_public_key << ", " << txkey.sec << ")");
    r = crypto::derive_public_key(derivation, 0, miner_address.m_spend_public_key, out_eph_public_key);
    CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << "0" << ", "<< miner_address.m_spend_public_key << ")");

    if (hard_fork_version >= HF_VERSION_VIEW_TAGS) {
      // Enforce the use of view_tags
      crypto::view_tag view_tag;
      crypto::derive_view_tag(derivation, 0, view_tag);
      txout_haven_tagged_key ttk;
      ttk.asset_type = "XHV";
      ttk.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
      ttk.is_collateral = false;
      ttk.is_collateral_change = false;
      ttk.key = out_eph_public_key;
      ttk.view_tag = view_tag;

      tx_out out;
      summary_amounts += out.amount = block_reward;
      out.target = ttk;
      tx.vout.push_back(out);

    } else {
      // Allow outputs without view_tags
      txout_haven_key tk;
      tk.asset_type = "XHV";
      tk.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
      tk.is_collateral = false;
      tk.is_collateral_change = false;
      tk.key = out_eph_public_key;

      tx_out out;
      summary_amounts += out.amount = block_reward;
      out.target = tk;
      tx.vout.push_back(out);
    }
    
    /*
    // Add the genesis amounts FOR TESTNET ONLY
    if (nettype == cryptonote::TESTNET && height == 0 && already_generated_coins == 0) {

      // First additional genesis amount
      r = crypto::derive_public_key(derivation, 1, miner_address.m_spend_public_key, out_eph_public_key);
      CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", 1, "<< miner_address.m_spend_public_key << ")");
      
      txout_haven_key tk_miner;
      tk_miner.asset_type = "XHV";
      tk_miner.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
      tk_miner.is_collateral = false;
      tk_miner.is_collateral_change = false;
      tk_miner.key = out_eph_public_key;
      
      tx_out out_miner;
      out_miner.amount = HAVEN_MAX_TX_VALUE_TESTNET;
      out_miner.target = tk_miner;
      tx.vout.push_back(out_miner);
    }
    */
    
    // add governance wallet output for xhv
    cryptonote::address_parse_info governance_wallet_address;
    crypto::view_tag view_tag;
    if (hard_fork_version >= 3) {
      if (already_generated_coins != 0)
      {
        add_tx_pub_key_to_extra(tx, gov_key.pub);
        cryptonote::get_account_address_from_str(governance_wallet_address, nettype, get_governance_address(hard_fork_version, nettype));
        crypto::public_key out_eph_public_key = AUTO_VAL_INIT(out_eph_public_key);
        if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, 1 /* second output in miner tx */, out_eph_public_key, view_tag))
        {
          MERROR("Failed to generate deterministic output key for governance wallet output creation");
          return false;
        }

        if (hard_fork_version >= HF_VERSION_VIEW_TAGS) {
          // Enforce the use of view_tags
          txout_haven_tagged_key ttk;
          ttk.view_tag = view_tag;
          ttk.asset_type = "XHV";
          ttk.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
          ttk.is_collateral = false;
          ttk.is_collateral_change = false;
          ttk.key = out_eph_public_key;
          tx_out out;
          summary_amounts += out.amount = governance_reward;
          if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
            out.amount += offshore_fee_map["XHV"];
          }

          out.target = ttk;
          tx.vout.push_back(out);
        } else {
          txout_haven_key tk;
          tk.asset_type = "XHV";
          tk.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
          tk.is_collateral = false;
          tk.is_collateral_change = false;
          tk.key = out_eph_public_key;
          tx_out out;
          summary_amounts += out.amount = governance_reward;
          if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
            out.amount += offshore_fee_map["XHV"];
          }

          out.target = tk;
          tx.vout.push_back(out);
        }
        CHECK_AND_ASSERT_MES(summary_amounts == (block_reward + governance_reward), false, "Failed to construct miner tx, summary_amounts = " << summary_amounts << " not equal total block_reward = " << (block_reward + governance_reward));
      }
    }

    if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
      // Add all of the outputs for all of the currencies in the contained TXs
      uint64_t idx = 2;
      for (auto &fee_map_entry: fee_map) {
        // Skip XHV - we have already handled that above
        if (fee_map_entry.first == "XHV")
          continue;
    
        if (fee_map_entry.second != 0) {
          uint64_t block_reward_xasset = fee_map_entry.second;
          uint64_t governance_reward_xasset = 0;
          governance_reward_xasset = get_governance_reward(height, fee_map_entry.second);
          block_reward_xasset -= governance_reward_xasset;

          // Add the conversion fee to the governance payment (if provided)
          if (offshore_fee_map[fee_map_entry.first] != 0) {
            governance_reward_xasset += offshore_fee_map[fee_map_entry.first];
          }
          
          // handle xasset converion fees
          if (hard_fork_version >= HF_VERSION_XASSET_FEES_V2) {
            if (xasset_fee_map[fee_map_entry.first] != 0) {
              if (hard_fork_version >= HF_VERSION_USE_COLLATERAL) {
                // we got 1.5% from xasset conversions.
                // 80% of it(1.2% of the inital value) goes to governance wallet
                // 20% of it(0.3% of the inital value) goes to miners
                boost::multiprecision::uint128_t fee = xasset_fee_map[fee_map_entry.first];
                // 80%
                governance_reward_xasset += (uint64_t)((fee * 4) / 5);
                // 20%
                block_reward_xasset += (uint64_t)(fee /5);
              } else {
                // we got 0.5% from xasset conversions. Here we wanna burn 80%(0.4% of the initial whole) of it and 
                // spilit the rest between governance wallet and the miner
                uint64_t fee = xasset_fee_map[fee_map_entry.first];
                // burn 80%
                fee -= (fee * 4) / 5;
                // split the rest
                block_reward_xasset += fee / 2;
                governance_reward_xasset += fee / 2;
              }
            }
          }

          // Miner component of the xAsset TX fee
          r = crypto::derive_public_key(derivation, idx, miner_address.m_spend_public_key, out_eph_public_key);
          CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << idx << ", "<< miner_address.m_spend_public_key << ")");
          idx++;
          crypto::view_tag view_tag;

          if (hard_fork_version >= HF_VERSION_VIEW_TAGS) {
            // Enforce the use of view_tags
            crypto::derive_view_tag(derivation, idx, view_tag);
            txout_haven_tagged_key ttk_miner;
            ttk_miner.asset_type = fee_map_entry.first;
            ttk_miner.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
            ttk_miner.is_collateral = false;
            ttk_miner.is_collateral_change = false;
            ttk_miner.key = out_eph_public_key;
            ttk_miner.view_tag = view_tag;
            tx_out out_miner;
            out_miner.amount = block_reward_xasset;
            out_miner.target = ttk_miner;
            tx.vout.push_back(out_miner);
          } else {
            txout_haven_key tk_miner;
            tk_miner.asset_type = fee_map_entry.first;
            tk_miner.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
            tk_miner.is_collateral = false;
            tk_miner.is_collateral_change = false;
            tk_miner.key = out_eph_public_key;
            
            tx_out out_miner;
            out_miner.amount = block_reward_xasset;
            out_miner.target = tk_miner;
            tx.vout.push_back(out_miner);
          }

          crypto::public_key out_eph_public_key_xasset = AUTO_VAL_INIT(out_eph_public_key_xasset);
          if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, idx /* n'th output in miner tx */, out_eph_public_key_xasset, view_tag))
          {
            MERROR("Failed to generate deterministic output key for governance wallet output creation (2)");
            return false;
          }
          idx++;

          if (hard_fork_version >= HF_VERSION_VIEW_TAGS) {
            // Enforce the use of view_tags
            txout_haven_tagged_key ttk_gov;
            ttk_gov.asset_type = fee_map_entry.first;
            ttk_gov.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
            ttk_gov.is_collateral = false;
            ttk_gov.is_collateral_change = false;
            ttk_gov.key = out_eph_public_key_xasset;
            ttk_gov.view_tag = view_tag;            
            tx_out out_gov;
            out_gov.amount = governance_reward_xasset;
            out_gov.target = ttk_gov;
            tx.vout.push_back(out_gov);
          } else {
            txout_haven_key tk_gov;
            tk_gov.asset_type = fee_map_entry.first;
            tk_gov.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
            tk_gov.is_collateral = false;
            tk_gov.is_collateral_change = false;
            tk_gov.key = out_eph_public_key_xasset;
            
            tx_out out_gov;
            out_gov.amount = governance_reward_xasset;
            out_gov.target = tk_gov;
            tx.vout.push_back(out_gov);
          }
        }
      }
    }

    // set tx version
    if (hard_fork_version >= HF_VERSION_USE_HAVEN_TYPES) {
      tx.version = HAVEN_TYPES_TRANSACTION_VERSION;
    } else if (hard_fork_version >= HF_VERSION_USE_COLLATERAL) {
      tx.version = COLLATERAL_TRANSACTION_VERSION;
    } else if (hard_fork_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
      tx.version = POU_TRANSACTION_VERSION;
    } else if (hard_fork_version >= HF_VERSION_HAVEN2) {
      tx.version = 5;
    } else if (hard_fork_version >= HF_VERSION_XASSET_FEES_V2) {
      tx.version = 4;
    } else if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
      tx.version = 3;
    } else {
      tx.version = 2;
    }

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);
    tx.invalidate_hashes();

    // per-output-unlock times
    if (hard_fork_version >= HF_PER_OUTPUT_UNLOCK_VERSION)
      for (size_t i=0; i<tx.vout.size(); i++)
        tx.output_unlock_times.push_back(tx.unlock_time);
    
    //LOG_PRINT("MINER_TX generated ok, block_reward=" << print_money(block_reward) << "("  << print_money(block_reward - fee) << "+" << print_money(fee)
    //  << "), current_block_size=" << current_block_size << ", already_generated_coins=" << already_generated_coins << ", tx_id=" << get_transaction_hash(tx), LOG_LEVEL_2);
    return true;
  }

  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr)
  {
    account_public_address addr = {null_pkey, null_pkey};
    size_t count = 0;
    for (const auto &i : destinations)
    {
      if (i.amount == 0)
        continue;
      if (change_addr && i.addr == *change_addr)
        continue;
      if (i.addr == addr)
        continue;
      if (count > 0)
        return null_pkey;
      addr = i.addr;
      ++count;
    }
    if (count == 0 && change_addr)
      return change_addr->m_view_public_key;
    return addr.m_view_public_key;
  }
  //---------------------------------------------------------------
  uint64_t get_governance_reward(uint64_t height, uint64_t base_reward)
  {
    return base_reward / 20;
  }
  //---------------------------------------------------------------
  bool validate_governance_reward_key(uint64_t height, const std::string& governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, cryptonote::network_type nettype)
  {
    keypair gov_key = get_deterministic_keypair_from_height(height);

    cryptonote::address_parse_info governance_wallet_address;
    cryptonote::get_account_address_from_str(governance_wallet_address, nettype, governance_wallet_address_str);
    crypto::public_key correct_key;
    crypto::view_tag view_tag;

    if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, output_index, correct_key, view_tag))
    {
      MERROR("Failed to generate deterministic output key for governance wallet output validation");
      return false;
    }

    return correct_key == output_key;
  }
  //---------------------------------------------------------------
  std::string get_governance_address(uint32_t version, network_type nettype) {
    if (version >= HF_VERSION_XASSET_FULL) {
      if (nettype == TESTNET) {
        return ::config::testnet::GOVERNANCE_WALLET_ADDRESS_MULTI;
      } else if (nettype == STAGENET) {
        return ::config::stagenet::GOVERNANCE_WALLET_ADDRESS_MULTI;
      } else {
        return ::config::GOVERNANCE_WALLET_ADDRESS_MULTI_NEW;
      }
    } else if (version >= 4) {
      if (nettype == TESTNET) {
        return ::config::testnet::GOVERNANCE_WALLET_ADDRESS_MULTI;
      } else if (nettype == STAGENET) {
        return ::config::stagenet::GOVERNANCE_WALLET_ADDRESS_MULTI;
      } else {
        return ::config::GOVERNANCE_WALLET_ADDRESS_MULTI;
      }
    } else {
      if (nettype == TESTNET) {
        return ::config::testnet::GOVERNANCE_WALLET_ADDRESS;
      } else if (nettype == STAGENET) {
        return ::config::stagenet::GOVERNANCE_WALLET_ADDRESS;
      } else {
        return ::config::GOVERNANCE_WALLET_ADDRESS;
      }
    }
  }
  //---------------------------------------------------------------
  uint64_t get_offshore_fee(const std::vector<cryptonote::tx_destination_entry>& dsts, const uint32_t unlock_time, const uint8_t hf_version) {

    // Calculate the amount being sent
    uint64_t amount = 0;
    for (auto dt: dsts) {
      // Filter out the change, which is never converted
      if (dt.dest_asset_type == "XUSD" && !dt.is_collateral) {
        amount += dt.amount + dt.slippage;
      }
    }

    uint64_t fee_estimate = 0;
    if (hf_version >= HF_VERSION_USE_COLLATERAL) {
      // Flat 1.5% fee
      fee_estimate = (amount * 3) / 200;
    } else if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
      // Flat 0.5% fee
      fee_estimate = amount / 200;
    } else {
      // The tests have to be written largest unlock_time first, as it is possible to delay the construction of the TX using GDB etc
      // which would otherwise cause the umlock_time to fall through the gaps and give a minimum fee for a short unlock_time.
      // This way, the code is safe, and the fee is always correct.
      fee_estimate =
      (unlock_time >= 5040) ? (amount / 500) :
      (unlock_time >= 1440) ? (amount / 20) :
      (unlock_time >= 720) ? (amount / 10) :
      amount / 5;
    }

    return fee_estimate;
  }
  //---------------------------------------------------------------
  uint64_t get_onshore_fee(const std::vector<cryptonote::tx_destination_entry>& dsts, const uint32_t unlock_time, const uint8_t hf_version) {

    // Calculate the amount being sent
    uint64_t amount_usd = 0;
    for (auto dt: dsts) {
      // Filter out the change, which is never converted
      if (dt.dest_asset_type == "XHV" && !dt.is_collateral && !dt.is_collateral_change) {
        amount_usd += dt.amount + dt.slippage;
      }
    }

    uint64_t fee_estimate = 0;
    if (hf_version >= HF_VERSION_USE_COLLATERAL) {
      // Flat 1.5% fee
      fee_estimate = (amount_usd * 3) / 200;
    } else if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
      // Flat 0.5% fee
      fee_estimate = amount_usd / 200;
    } else {
      // The tests have to be written largest unlock_time first, as it is possible to delay the construction of the TX using GDB etc
      // which would otherwise cause the umlock_time to fall through the gaps and give a minimum fee for a short unlock_time.
      // This way, the code is safe, and the fee is always correct.
      fee_estimate =
      (unlock_time >= 5040) ? (amount_usd / 500) :
      (unlock_time >= 1440) ? (amount_usd / 20) :
      (unlock_time >= 720) ? (amount_usd / 10) :
      amount_usd / 5;

    }

    return fee_estimate;
  }
  //---------------------------------------------------------------
  uint64_t get_xasset_to_xusd_fee(const std::vector<cryptonote::tx_destination_entry>& dsts, const uint8_t hf_version) {

    // Calculate the amount being sent
    uint64_t amount_xasset = 0;
    for (auto dt: dsts) {
      // Filter out the change, which is never converted
      if (dt.dest_asset_type == "XUSD") {
        amount_xasset += dt.amount + dt.slippage;
      }
    }

    uint64_t fee_estimate = 0;  
    if (hf_version >= HF_VERSION_USE_COLLATERAL) {
      // Calculate 1.5% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_xasset;
      amount_128 = (amount_128 * 15) / 1000; // 1.5%
      fee_estimate  = (uint64_t)amount_128;
    } else if (hf_version >= HF_VERSION_XASSET_FEES_V2) {
      // Calculate 0.5% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_xasset;
      amount_128 = (amount_128 * 5) / 1000; // 0.5%
      fee_estimate  = (uint64_t)amount_128;
    } else {
      // Calculate 0.3% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_xasset;
      amount_128 = (amount_128 * 3) / 1000;
      fee_estimate = (uint64_t)amount_128;
    }

   return fee_estimate;
  }
  //---------------------------------------------------------------
  uint64_t get_xusd_to_xasset_fee(const std::vector<cryptonote::tx_destination_entry>& dsts, const uint8_t hf_version) {

    // Calculate the amount being sent
    uint64_t amount_usd = 0;
    for (auto dt: dsts) {
      // Filter out the change, which is never converted
      // All other destinations should have both pre and post converted amounts set so far except
      // the change destinations.
      if (dt.dest_asset_type != "XUSD") {
        amount_usd += dt.amount + dt.slippage;
      }
    }

    uint64_t fee_estimate = 0;
    if (hf_version >= HF_VERSION_USE_COLLATERAL) {
      // Calculate 1.5% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_usd;
      amount_128 = (amount_128 * 15) / 1000; // 1.5%
      fee_estimate  = (uint64_t)amount_128;
    } else if (hf_version >= HF_VERSION_XASSET_FEES_V2) {
      // Calculate 0.5% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_usd;
      amount_128 = (amount_128 * 5) / 1000; // 0.5%
      fee_estimate  = (uint64_t)amount_128;
    } else {
      // Calculate 0.3% of the total being sent
      boost::multiprecision::uint128_t amount_128 = amount_usd;
      amount_128 = (amount_128 * 3) / 1000;
      fee_estimate = (uint64_t)amount_128;
    }

    return fee_estimate;
  }
  //---------------------------------------------------------------
  bool get_tx_type(const std::string& source, const std::string& destination, transaction_type& type) {

    // check both source and destination are supported.
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), source) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Source Asset type " << source << " is not supported! Rejecting..");
      return false;
    }
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), destination) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Destination Asset type " << destination << " is not supported! Rejecting..");
      return false;
    }

    // Find the tx type
    if (source == destination) {
      if (source == "XHV") {
        type = transaction_type::TRANSFER;
      } else if (source == "XUSD") {
        type = transaction_type::OFFSHORE_TRANSFER;
      } else {
        type = transaction_type::XASSET_TRANSFER;
      }
    } else {
      if (source == "XHV" && destination == "XUSD") {
        type = transaction_type::OFFSHORE;
      } else if (source == "XUSD" && destination == "XHV") {
        type = transaction_type::ONSHORE;
      } else if (source == "XUSD" && destination != "XHV") {
        type = transaction_type::XUSD_TO_XASSET;
      } else if (destination == "XUSD" && source != "XHV") {
        type = transaction_type::XASSET_TO_XUSD;
      } else {
        LOG_ERROR("Invalid conversion from " << source << "to" << destination << ". Rejecting..");
        return false;
      }
    }

    // Return success to caller
    return true;
  }
  //---------------------------------------------------------------
  bool get_slippage(const transaction_type &tx_type, const std::string &source_asset, const std::string &dest_asset, const uint64_t amount, uint64_t &slippage, const offshore::pricing_record &pr, const std::vector<std::pair<std::string, std::string>> &amounts, const uint8_t hf_version)
  {
    using namespace boost::multiprecision;
    using tt = cryptonote::transaction_type;

    // Fail dismally if we have been called too early
    if (hf_version < HF_VERSION_SLIPPAGE) {
      LOG_ERROR("get_slippage() called from a pre-slippage client - aborting");
      return false;
    }
    
    // Do the right thing based upon TX type
    if (tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER) {
      slippage = 0;
      return true;
    }

    // Process the circulating supply data
    std::map<std::string, uint128_t> map_amounts;
    uint128_t mcap_xassets = 0;
    for (const auto &i: amounts)
    {
      // Copy into the map for expediency
      map_amounts[i.first] = uint128_t(i.second.c_str());

      // Exclude XHV from the xAssets MCAP
      if (i.first == "XHV") continue;

      // Get the pricing data for the xAsset
      uint128_t price_xasset = pr.spot(i.first);
      
      // Multiply by the amount of coin in circulation
      uint128_t amount_xasset(i.second.c_str());

      // Skip scaling of xUSD, because price uses notional peg rather than actual value
      if (i.first != "xUSD") {
        amount_xasset *= COIN;
        amount_xasset /= price_xasset;
      }      

      // Sum into our total for all xAssets
      mcap_xassets += amount_xasset;
    }

    // Check for seeding of pools
    if (!map_amounts.count(dest_asset) || map_amounts[dest_asset] == 0) {
      slippage = 0;
      return true;
    }

    // Calculate the XHV market cap for spot + MA
    uint128_t mcap_xhv_spot = map_amounts["XHV"];
    mcap_xhv_spot *= pr.spot("XHV");
    mcap_xhv_spot /= COIN;
    uint128_t mcap_xhv_ma = map_amounts["XHV"];
    mcap_xhv_ma *= pr.ma("XHV");
    mcap_xhv_ma /= COIN;

    // Take a copy of the amount to convert
    uint128_t convert_amount = amount;
    
    // Calculate the source pool %
    cpp_bin_float_quad src_pool_ratio = convert_amount.convert_to<cpp_bin_float_quad>() / map_amounts[source_asset].convert_to<cpp_bin_float_quad>();

    // Calculate the source pool multiplier
    cpp_bin_float_quad src_pool_multiplier = pow((sqrt(pow((src_pool_ratio * 7.0), 0.5)) + 1.0), 5.0);

    // Calculate the source pool slippage
    cpp_bin_float_quad src_pool_slippage = src_pool_ratio * src_pool_multiplier;

    // Calculate the dest pool ratio and multiplier 
    cpp_bin_float_quad dest_pool_ratio = 0.0;
    cpp_bin_float_quad dest_pool_multiplier = 5.0;
    if (tx_type == tt::ONSHORE) {
      uint128_t dpr_numerator = convert_amount * COIN;
      uint128_t dpr_denominator = map_amounts["XHV"] * std::min(pr.spot("XHV"), pr.ma("XHV"));
      dest_pool_ratio = dpr_numerator.convert_to<cpp_bin_float_quad>() / dpr_denominator.convert_to<cpp_bin_float_quad>();
      dest_pool_multiplier = pow((sqrt(pow(dest_pool_ratio, 0.4)) + 1.0), 15.0);
    } else if (tx_type == tt::OFFSHORE) {
      //dest_pool_ratio = (convert_amount * std::max(pr.spot("XHV"), pr.ma("XHV")) / (map_amounts["xUSD"] * std::min(pr.spot("xUSD"), pr.ma("xUSD"))));
      uint128_t dpr_numerator = convert_amount * std::max(pr.spot("XHV"), pr.ma("XHV"));
      uint128_t dpr_denominator = map_amounts["xUSD"] * std::min(pr.spot("xUSD"), pr.ma("xUSD"));
      dest_pool_ratio = dpr_numerator.convert_to<cpp_bin_float_quad>() / dpr_denominator.convert_to<cpp_bin_float_quad>();
    } else if (tx_type == tt::XASSET_TO_XUSD) {
      //dest_pool_ratio = (convert_amount * COIN) / (map_amounts[dest_asset] * min(pr.spot("xUSD"), pr.ma("xUSD")));
      uint128_t dpr_numerator = convert_amount * COIN;
      uint128_t dpr_denominator = map_amounts[dest_asset] * std::min(pr.spot("xUSD"), pr.ma("xUSD"));
      dest_pool_ratio = dpr_numerator.convert_to<cpp_bin_float_quad>() / dpr_denominator.convert_to<cpp_bin_float_quad>();
    } else if (tx_type == tt::XUSD_TO_XASSET) {
      //dest_pool_ratio = (convert_amount * pr.spot(source_asset)) / (map_amounts[dest_asset] * pr.spot(dest_asset));
      uint128_t dpr_numerator = convert_amount * pr.spot(source_asset);
      uint128_t dpr_denominator = map_amounts[dest_asset] * pr.spot(dest_asset);
      dest_pool_ratio = dpr_numerator.convert_to<cpp_bin_float_quad>() / dpr_denominator.convert_to<cpp_bin_float_quad>();
    } else {
      // Not a valid transaction type for slippage
      LOG_ERROR("Invalid transaction type specified for get_slippage() - aborting");
      return false;
    }

    // Calculate the dest pool slippage
    cpp_bin_float_quad dest_pool_slippage = dest_pool_ratio * dest_pool_multiplier;

    // Calculate basic_slippage
    cpp_bin_float_quad basic_slippage = src_pool_slippage + dest_pool_slippage;

    // Calculate Mcap ratio slippage
    cpp_bin_float_quad mcap_ratio_slippage = 0.0;
    if (tx_type == tt::ONSHORE || tx_type == tt::OFFSHORE) {
    
      // Calculate Mcap Ratio for XHV spot
      cpp_bin_float_quad mcr_sp = mcap_xassets.convert_to<cpp_bin_float_quad>() / mcap_xhv_spot.convert_to<cpp_bin_float_quad>();

      // Calculate Mcap Ratio for XHV MA
      cpp_bin_float_quad mcr_ma = mcap_xassets.convert_to<cpp_bin_float_quad>() / mcap_xhv_ma.convert_to<cpp_bin_float_quad>();

      // Get the largest of these in a more usable format
      cpp_bin_float_quad mcr_max = (mcr_sp > mcr_ma) ? mcr_sp : mcr_ma;
      
      // Calculate the Mcap ratio slippage
      mcap_ratio_slippage = std::sqrt(std::pow(mcr_max.convert_to<double>(), 1.2)) / 6.0;
    }

    // Calculate xUSD Peg Slippage
    cpp_bin_float_quad xusd_peg_slippage = 0;
    if (std::min(pr.spot("xUSD"), pr.ma("xUSD")) < 1.0) {
      xusd_peg_slippage = std::sqrt(std::pow((1.0 - std::min(pr.spot("xUSD"), pr.ma("xUSD"))), 3.0)) / 1.3;
    }

    // Calculate the xBTC Mcap Ratio Slippage
    cpp_bin_float_quad xbtc_mcap_ratio_slippage = 0.0;
    if (tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD) {

      // Calculate the xBTC Mcap
      cpp_bin_float_quad mcap_xbtc = map_amounts["xBTC"].convert_to<cpp_bin_float_quad>();
      mcap_xbtc *= COIN;
      mcap_xbtc /= pr.spot("xBTC");
      
      // Calculate the xUSD Mcap
      cpp_bin_float_quad mcap_xusd = map_amounts["xUSD"].convert_to<cpp_bin_float_quad>();
      mcap_xusd *= COIN;
      mcap_xusd /= std::min(pr.spot("xUSD"), pr.ma("xUSD"));

      // Update the xBTC Mcap Ratio Slippage
      xbtc_mcap_ratio_slippage = std::sqrt(std::pow((mcap_xbtc / mcap_xusd).convert_to<double>(), 1.4)) / 10.0;
    }

    // Calculate the total slippage
    cpp_bin_float_quad total_slippage =
      (tx_type == tt::ONSHORE || tx_type == tt::OFFSHORE) ? basic_slippage + std::max(mcap_ratio_slippage, xusd_peg_slippage) :
      (tx_type == tt::XUSD_TO_XASSET && dest_asset == "xBTC") ? basic_slippage + std::max(xbtc_mcap_ratio_slippage, xusd_peg_slippage) :
      basic_slippage + xusd_peg_slippage;

    // Limit total_slippage to 99% so that the code doesn't break
    if (total_slippage > 0.99) total_slippage = 0.99;
    total_slippage *= convert_amount.convert_to<cpp_bin_float_quad>();
    slippage = total_slippage.convert_to<uint64_t>();
    slippage -= (slippage % 100000000);
    return true;
  }
  //---------------------------------------------------------------
  bool get_collateral_requirements(const transaction_type &tx_type, const uint64_t amount, uint64_t &collateral, const offshore::pricing_record &pr, const std::vector<std::pair<std::string, std::string>> &amounts, const uint8_t hf_version)
  {
    using namespace boost::multiprecision;
    using tt = transaction_type;

    // Process the circulating supply data
    std::map<std::string, uint128_t> map_amounts;
    uint128_t mcap_xassets = 0;
    for (const auto &i: amounts)
    {
      // Copy into the map for expediency
      map_amounts[i.first] = uint128_t(i.second.c_str());
      
      // Skip XHV
      if (i.first == "XHV") continue;

      // Get the pricing data for the xAsset
      uint128_t price_xasset = pr.spot(i.first);
      
      // Multiply by the amount of coin in circulation
      uint128_t amount_xasset(i.second.c_str());
      amount_xasset *= COIN;
      amount_xasset /= price_xasset;
      
      // Sum into our total for all xAssets
      mcap_xassets += amount_xasset;
    }

    // Calculate the XHV market cap
    /*
    boost::multiprecision::uint128_t price_xhv =
      (tx_type == tt::OFFSHORE) ? std::min(pr.unused1, pr.xUSD) :
      (tx_type == tt::ONSHORE)  ? std::max(pr.unused1, pr.xUSD) :
      0;
    */
    boost::multiprecision::uint128_t price_xhv =
      (tx_type == tt::OFFSHORE) ? pr.min("XHV") :
      (tx_type == tt::ONSHORE)  ? pr.max("XHV") :
      0;
    uint128_t mcap_xhv = map_amounts["XHV"];
    mcap_xhv *= price_xhv;
    mcap_xhv /= COIN;

    // Calculate the market cap ratio
    cpp_bin_float_quad ratio_mcap_128 = mcap_xassets.convert_to<cpp_bin_float_quad>() / mcap_xhv.convert_to<cpp_bin_float_quad>();
    double ratio_mcap = ratio_mcap_128.convert_to<double>();

    // Do the right thing, based on the HF version
    if (hf_version >= HF_VERSION_SLIPPAGE) {

      // Force the VBS rate to 1.0, irrespective of health of network - let slippage pick up the slack
      if (tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER || tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD) {

        // No collateral needed
        collateral = 0;
        
      } else {

        // Convert amount to 128 bit
        boost::multiprecision::uint128_t amount_128 = amount;

        // Check for onshore TX
        if (tx_type == tt::ONSHORE) {
          // Scale the amount
          amount_128 *= COIN;
          amount_128 /= price_xhv;
        }
        
        // Collateral is equal to amount being converted
        collateral = amount_128.convert_to<uint64_t>();
      }

      // Done - return to caller
      return true;
      
    } else if (hf_version >= HF_VERSION_USE_COLLATERAL_V2) {

      if (tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER || tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD) {
        collateral = 0;
      } else {
        // VBS multiplier changes between onshore and offshore TXs
        double vbs_scale = (tx_type == tt::ONSHORE) ? 9.0 : 4.0;
        double vbs = std::floor(sqrt(ratio_mcap) * vbs_scale);
        vbs = std::min(10.0, std::max(vbs, 1.0));

        // Convert amount to 128 bit
        boost::multiprecision::uint128_t amount_128 = amount;

        // Check for onshore TX
        if (tx_type == tt::ONSHORE) {
          // Scale the amount
          amount_128 *= COIN;
          amount_128 /= price_xhv;
        }
        
        // Get the collateral amount
        boost::multiprecision::uint128_t collateral_128 = static_cast<uint64_t>(vbs);
        collateral_128 *= amount_128;
        collateral = collateral_128.convert_to<uint64_t>();
        LOG_PRINT_L1("Conversion TX requires " << print_money(collateral) << " XHV as collateral to convert " << print_money(amount) << (tx_type == tt::OFFSHORE) ? " XHV" : " XUSD");
      }
      return true;
    }
    
    // Calculate the spread ratio
    double ratio_spread = (ratio_mcap >= 1.0) ? 0.0 : 1.0 - ratio_mcap;
    
    // Calculate the MCAP VBS rate
    double rate_mcvbs = (ratio_mcap == 0) ? 0 : (ratio_mcap < 0.9) // Fix for "possible" 0 ratio
      ? std::exp((ratio_mcap + std::sqrt(ratio_mcap))*2.0) - 0.5 // Lower MCAP ratio
      : std::sqrt(ratio_mcap) * 40.0; // Higher MCAP ratio

    // Calculate the Spread Ratio VBS rate
    double rate_srvbs = std::exp(1 + std::sqrt(ratio_spread)) + rate_mcvbs + 1.5;
    
    // Set the Slippage Multiplier
    double slippage_multiplier = 10.0;

    // Convert amount to 128 bit
    boost::multiprecision::uint128_t amount_128 = amount;
  
    // Do the right thing based upon TX type
    if (tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER) {
      collateral = 0;
    } else if (tx_type == tt::OFFSHORE) {

      // Calculate MCRI
      boost::multiprecision::uint128_t amount_usd_128 = amount;
      amount_usd_128 *= price_xhv;
      amount_usd_128 /= COIN;
      cpp_bin_float_quad ratio_mcap_new_quad = ((amount_usd_128.convert_to<cpp_bin_float_quad>() + mcap_xassets.convert_to<cpp_bin_float_quad>()) /
						(mcap_xhv.convert_to<cpp_bin_float_quad>() - amount_usd_128.convert_to<cpp_bin_float_quad>()));
      double ratio_mcap_new = ratio_mcap_new_quad.convert_to<double>();
      double ratio_mcri = (ratio_mcap == 0.0) ? ratio_mcap_new : (ratio_mcap_new / ratio_mcap) - 1.0;
      ratio_mcri = std::abs(ratio_mcri);

      // Calculate Offshore Slippage VBS rate
      if (ratio_mcap_new <= 0.1) slippage_multiplier = 3.0;
      double rate_offsvbs = std::sqrt(ratio_mcri) * slippage_multiplier;

      // Calculate the combined VBS (collateral + "slippage")
      double vbs = rate_mcvbs + rate_offsvbs;
      const double min_vbs = 1.0;
      vbs = std::max(vbs, min_vbs);
      vbs = std::floor(vbs);
      vbs *= COIN;
      boost::multiprecision::uint128_t collateral_128 = static_cast<uint64_t>(vbs);
      collateral_128 *= amount_128;
      collateral_128 /= COIN;
      collateral = collateral_128.convert_to<uint64_t>();

      LOG_PRINT_L1("Offshore TX requires " << print_money(collateral) << " XHV as collateral to convert " << print_money(amount) << " XHV");
    
    } else if (tx_type == tt::ONSHORE) {

      // Calculate SRI
      cpp_bin_float_quad ratio_mcap_new_quad = ((mcap_xassets.convert_to<cpp_bin_float_quad>() - amount_128.convert_to<cpp_bin_float_quad>()) /
						(mcap_xhv.convert_to<cpp_bin_float_quad>() + amount_128.convert_to<cpp_bin_float_quad>()));
      double ratio_mcap_new = ratio_mcap_new_quad.convert_to<double>();
      double ratio_sri = (ratio_mcap == 0.0) ? (-1.0 * ratio_mcap_new) : ((1.0 - ratio_mcap_new) / (1.0 - ratio_mcap)) - 1.0;
      ratio_sri = std::max(ratio_sri, 0.0);
      
      // Calculate ONSVBS
      //if (ratio_mcap_new <= 0.1) slippage_multiplier = 3.0;
      //double rate_onsvbs = std::sqrt(ratio_sri) * slippage_multiplier;
      double rate_onsvbs = std::sqrt(ratio_sri) * 3.0;
  
      // Calculate the combined VBS (collateral + "slippage")
      double vbs = std::max(rate_mcvbs, rate_srvbs) + rate_onsvbs;
      const double min_vbs = 1.0;
      vbs = std::max(vbs, min_vbs);
      vbs = std::floor(vbs);
      vbs *= COIN;
      boost::multiprecision::uint128_t collateral_128 = static_cast<uint64_t>(vbs);
      collateral_128 *= amount_128;
      collateral_128 /= price_xhv;
      collateral = collateral_128.convert_to<uint64_t>();

      boost::multiprecision::uint128_t amount_usd_128 = amount;
      amount_usd_128 *= price_xhv;
      amount_usd_128 /= COIN;
      LOG_PRINT_L1("Onshore TX requires " << print_money(collateral) << " XHV as collateral to convert " << print_money((uint64_t)amount_128) << " xUSD");
    
    } else if (tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD) {
      collateral = 0;
    } else {
      // Throw a wallet exception - should never happen
      MERROR("Invalid TX type");
      return false;
    }

    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_block_cap(const std::vector<std::pair<std::string, std::string>>& supply_amounts, const offshore::pricing_record& pr, const uint8_t hf_version)
  {
    // From the introduction of slippage, the block cap was effectively superfluous. This was achieved by using the max TX value as the block cap
    if (hf_version >= HF_VERSION_SLIPPAGE) {
      return HAVEN_MAX_TX_VALUE;
    }
    
    std::string str_xhv_supply;
    for (const auto& supply: supply_amounts) {
      if (supply.first == "XHV") {
        str_xhv_supply = supply.second;
        break;
      }
    }

    // get supply
    boost::multiprecision::uint128_t xhv_supply_128(str_xhv_supply);
    xhv_supply_128 /= COIN;
    uint64_t xhv_supply = xhv_supply_128.convert_to<uint64_t>();

    // get price
    double price = (double)(pr.min("XHV"));//std::min(pr.unused1, pr.xUSD)); // smaller of the ma vs spot
    price /= COIN;

    // market cap
    uint64_t xhv_market_cap = xhv_supply * price;
    
    return (pow(xhv_market_cap * 3000, 0.42) + ((xhv_supply * 5) / 1000)) * COIN;
  }
  //---------------------------------------------------------------
  bool get_conversion_rate(const offshore::pricing_record& pr, const std::string& from_asset, const std::string& to_asset, uint64_t& rate) {
    // Check for transfers
    if (from_asset == to_asset) {
      rate = COIN;
      return true;
    }
    if (from_asset == "XHV") {
      // XHV as source
      if (to_asset == "XUSD") {
        // Scale to xUSD (offshore) and bail out (next line uses "&&" not "||" because historically a number of PRs didn't have both values present)
        if (!pr.spot("XHV") && !pr.ma("XHV")) {
          // Missing a rate that we need - return an error
          LOG_ERROR("Missing exchange rate for conversion (" << from_asset << "," << to_asset << ") - aborting");
          return false;
        }
        rate = pr.min("XHV");//std::min(pr.xUSD, pr.unused1);
      } else {
        // Scale to xUSD and then to the xAsset specified
        boost::multiprecision::uint128_t rate_128 = pr.spot("XHV");//pr.xUSD;
        rate_128 *= pr.spot(to_asset);//pr[to_asset];
        rate_128 /= COIN;
        rate = rate_128.convert_to<uint64_t>();
        rate -= (rate % 10000);
      }
    } else if (from_asset == "XUSD") {
      // xUSD as source
      if (to_asset == "XHV") {
        // Scale directly to XHV (onshore) and bail out (next line uses "&&" not "||" because historically a number of PRs didn't have both values present, see block #1010002)
        if (!pr.spot("XHV") && !pr.ma("XHV")) {
          // Missing a rate that we need - return an error
          LOG_ERROR("Missing exchange rate for conversion (" << from_asset << "," << to_asset << ") - aborting");
          return false;
        }
        boost::multiprecision::uint128_t rate_128 = COIN;
        rate_128 *= COIN;
        rate_128 /= pr.max("XHV");//std::max(pr.xUSD, pr.unused1);
        rate = rate_128.convert_to<uint64_t>();
        rate -= (rate % 10000);
        
      } else {
        // Scale directly to xAsset (xusd_to_xasset)
        if (!pr.spot(to_asset)) {
          // Missing a rate that we need - return an error
          LOG_ERROR("Missing exchange rate for conversion (" << from_asset << "," << to_asset << ") - aborting");
          return false;
        }
        rate = pr.spot(to_asset);
      }
    } else {
      // xAsset as source
      if ((to_asset != "XUSD") && (to_asset != "XHV")) {
        // Report an error and bail out
        LOG_ERROR("Invalid exchange rate for conversion (" << from_asset << "," << to_asset << ") - aborting");
        return false;
      }
      // scale to xUSD
      boost::multiprecision::uint128_t rate_128 = COIN;
      rate_128 *= COIN;
      rate_128 /= pr.spot(from_asset);
      if (to_asset == "XHV") {
        rate_128 *= COIN;
        rate_128 /= pr.max("XHV");//std::max(pr.xUSD, pr.unused1);
      }
      // truncate and bail out
      rate = rate_128.convert_to<uint64_t>();
      rate -= (rate % 10000);        
    }
    return true;
  }
  //---------------------------------------------------------------
  bool get_converted_amount(const uint64_t& conversion_rate, const uint64_t& source_amount, uint64_t& dest_amount) {
    if (!conversion_rate || !source_amount) {
      LOG_ERROR("Invalid conversion rate or input amount for conversion (" << conversion_rate << "," << source_amount << ") - aborting");
      return false;
    }
    boost::multiprecision::uint128_t source_amount_128 = source_amount;
    boost::multiprecision::uint128_t conversion_rate_128 = conversion_rate;
    boost::multiprecision::uint128_t dest_amount_128 = source_amount_128 * conversion_rate_128;
    dest_amount_128 /= COIN;
    dest_amount = dest_amount_128.convert_to<uint64_t>();
    return true;
  }
  //---------------------------------------------------------------
  uint64_t get_xasset_amount(const uint64_t xusd_amount, const std::string& to_asset_type, const offshore::pricing_record& pr)
  {
    boost::multiprecision::uint128_t xusd_128 = xusd_amount;
    boost::multiprecision::uint128_t exchange_128 = pr.spot(to_asset_type); 
    // Now work out the amount
    boost::multiprecision::uint128_t xasset_128 = xusd_128 * exchange_128;
    xasset_128 /= 1000000000000;

    return (uint64_t)xasset_128;
  }
  //---------------------------------------------------------------
  uint64_t get_xusd_amount(const uint64_t amount, const std::string& amount_asset_type, const offshore::pricing_record& pr, const transaction_type tx_type, uint8_t hf_version)
  {

    if (amount_asset_type == "XUSD") {
      return amount;
    }

    boost::multiprecision::uint128_t amount_128 = amount;
    boost::multiprecision::uint128_t exchange_128 = pr.spot(amount_asset_type);
    if (amount_asset_type == "XHV") {
      // xhv -> xusd
      if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
        if (tx_type == transaction_type::ONSHORE) {
          // Eliminate MA/spot advantage for onshore conversion
          exchange_128 = pr.max("XHV");//std::max(pr.unused1, pr.xUSD);
        } else {
          // Eliminate MA/spot advantage for offshore conversion
          exchange_128 = pr.min("XHV");//std::min(pr.unused1, pr.xUSD);
        }
      }
      boost::multiprecision::uint128_t xusd_128 = amount_128 * exchange_128;
      xusd_128 /= 1000000000000;
      return (uint64_t)xusd_128;
    } else {
      // xasset -> xusd
      boost::multiprecision::uint128_t xusd_128 = amount_128 * 1000000000000;
      xusd_128 /= exchange_128;
      return (uint64_t)xusd_128;
    }
  }
  //---------------------------------------------------------------
  uint64_t get_xhv_amount(const uint64_t xusd_amount, const offshore::pricing_record& pr, const transaction_type tx_type, uint8_t hf_version)
  {
    // Now work out the amount
    boost::multiprecision::uint128_t xusd_128 = xusd_amount;
    boost::multiprecision::uint128_t exchange_128 = pr.ma("XHV");
    boost::multiprecision::uint128_t xhv_128 = xusd_128 * 1000000000000;
    if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
      if (tx_type == transaction_type::ONSHORE) {
        // Eliminate MA/spot advantage for onshore conversion
        exchange_128 = pr.max("XHV");//std::max(pr.unused1, pr.xUSD);
      } else {
        // Eliminate MA/spot advantage for offshore conversion
        exchange_128 = pr.min("XHV");//std::min(pr.unused1, pr.xUSD);
      }
    }
    xhv_128 /= exchange_128;
    return (uint64_t)xhv_128;
  }
  //----------------------------------------------------------------------------------------------------
  bool tx_pr_height_valid(const uint64_t current_height, const uint64_t pr_height, const crypto::hash& tx_hash) {
    if (pr_height >= current_height) {
      return false;
    }
    if ((current_height - PRICING_RECORD_VALID_BLOCKS) > pr_height) {
      // exception for 1 tx that used 11 block old record and is already in the chain.
      if (epee::string_tools::pod_to_hex(tx_hash) != "3e61439c9f751a56777a1df1479ce70311755b9d42db5bcbbd873c6f09a020a6") {
        return false;
      }
    }
    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(
    const std::string& source_asset,
    const std::string& dest_asset,
    const offshore::pricing_record& pr,
    const account_keys& sender_account_keys,
    const std::unordered_map<crypto::public_key,
    subaddress_index>& subaddresses,
    std::vector<tx_source_entry>& sources,
    std::vector<tx_destination_entry>& destinations,
    const boost::optional<cryptonote::account_public_address>& change_addr,
    const std::vector<uint8_t> &extra,
    transaction& tx,
    uint64_t unlock_time,
    const uint8_t hf_version,
    const uint64_t current_height,
    const uint64_t onshore_col_amount,
    const uint64_t fee_xhv,
    const crypto::secret_key &tx_key,
    const std::vector<crypto::secret_key> &additional_tx_keys,
    bool rct,
    const rct::RCTConfig &rct_config,
    bool shuffle_outs,
    bool use_view_tags,
    network_type nettype
  ){

    hw::device &hwdev = sender_account_keys.get_device();

    if (sources.empty())
    {
      LOG_ERROR("Empty sources");
      return false;
    }

    std::vector<rct::key> amount_keys;
    tx.set_null();
    amount_keys.clear();

    // set version and unlock time
    if (hf_version >= HF_VERSION_USE_HAVEN_TYPES) {
      tx.version = HAVEN_TYPES_TRANSACTION_VERSION;
    } else if (hf_version >= HF_VERSION_USE_COLLATERAL) {
      tx.version = COLLATERAL_TRANSACTION_VERSION;
    } else if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION){
      tx.version = POU_TRANSACTION_VERSION;
    } else if (hf_version >= HF_VERSION_HAVEN2) {
      tx.version = 5;
    } else if (hf_version >= HF_VERSION_XASSET_FEES_V2) {
      tx.version = 4;
    } else if (hf_version >= HF_VERSION_CLSAG) {
      tx.version = 3;
    } else {
      tx.version = 2;
    }
    tx.unlock_time = (unlock_time - current_height) > CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE ? unlock_time : 0;

    // set ther pricing record height
    if (source_asset != dest_asset)
      tx.pricing_record_height = current_height;
    else
      tx.pricing_record_height = 0;

    tx.extra = extra;
    crypto::public_key txkey_pub;

    // if we have a stealth payment id, find it and encrypt it with the tx key now
    std::vector<tx_extra_field> tx_extra_fields;
    if (parse_tx_extra(tx.extra, tx_extra_fields))
    {
      bool add_dummy_payment_id = true;
      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash payment_id = null_hash;
        crypto::hash8 payment_id8 = null_hash8;
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          LOG_PRINT_L2("Encrypting payment id " << payment_id8);
          crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
          if (view_key_pub == null_pkey)
          {
            LOG_ERROR("Destinations have to have exactly one output to support encrypted payment ids");
            return false;
          }

          if (!hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key))
          {
            LOG_ERROR("Failed to encrypt payment id");
            return false;
          }

          std::string extra_nonce;
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          remove_field_from_tx_extra(tx.extra, typeid(tx_extra_nonce));
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add encrypted payment id to tx extra");
            return false;
          }
          LOG_PRINT_L1("Encrypted payment ID: " << payment_id8);
          add_dummy_payment_id = false;
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          add_dummy_payment_id = false;
        }
      }

      // we don't add one if we've got more than the usual 1 destination plus change
      if (destinations.size() > 2)
        add_dummy_payment_id = false;

      if (add_dummy_payment_id)
      {
        // if we have neither long nor short payment id, add a dummy short one,
        // this should end up being the vast majority of txes as time goes on
        std::string extra_nonce;
        crypto::hash8 payment_id8 = null_hash8;
        crypto::public_key view_key_pub = get_destination_view_key_pub(destinations, change_addr);
        if (view_key_pub == null_pkey)
        {
          LOG_ERROR("Failed to get key to encrypt dummy payment id with");
        }
        else
        {
          hwdev.encrypt_payment_id(payment_id8, view_key_pub, tx_key);
          set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
          if (!add_extra_nonce_to_tx_extra(tx.extra, extra_nonce))
          {
            LOG_ERROR("Failed to add dummy encrypted payment id to tx extra");
            // continue anyway
          }
        }
      }
    }
    else
    {
      MWARNING("Failed to parse tx extra");
      tx_extra_fields.clear();
    }

    struct input_generation_context_data
    {
      keypair in_ephemeral;
    };
    std::vector<input_generation_context_data> in_contexts;

    uint64_t summary_inputs_money = 0;
    //fill inputs
    int idx = -1;
    for(const tx_source_entry& src_entr:  sources)
    {
      ++idx;
      if(src_entr.real_output >= src_entr.outputs.size())
      {
        LOG_ERROR("real_output index (" << src_entr.real_output << ")bigger than output_keys.size()=" << src_entr.outputs.size());
        return false;
      }
      // exclude the collateral to be seen as input money
      if (src_entr.asset_type == source_asset)
        summary_inputs_money += src_entr.amount;

      //key_derivation recv_derivation;
      in_contexts.push_back(input_generation_context_data());
      keypair& in_ephemeral = in_contexts.back().in_ephemeral;
      crypto::key_image img;
      const auto& out_key = reinterpret_cast<const crypto::public_key&>(src_entr.outputs[src_entr.real_output].second.dest);
      if(!generate_key_image_helper(sender_account_keys, subaddresses, out_key, src_entr.real_out_tx_key, src_entr.real_out_additional_tx_keys, src_entr.real_output_in_tx_index, in_ephemeral,img, hwdev))
      {
        LOG_ERROR("Key image generation failed!");
        return false;
      }

      //check that derivated key is equal with real output key
      if(!(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      txin_haven_key input_to_key;
      input_to_key.amount = src_entr.amount;
      input_to_key.k_image = img;
      input_to_key.asset_type = src_entr.asset_type;

      //fill outputs array and use relative offsets
      for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
        input_to_key.key_offsets.push_back(out_entry.first);

      input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
      tx.vin.push_back(input_to_key);
    }

    // calculate offshore fees before shuffling destinations
    transaction_type tx_type;
    if (!get_tx_type(source_asset, dest_asset, tx_type)) {
      LOG_ERROR("invalid tx type");
      return false;
    }
    uint64_t fee = 0;
    uint64_t offshore_fee = 
    (tx_type == transaction_type::OFFSHORE) ? get_offshore_fee(destinations, unlock_time - current_height - 1, hf_version) :
    (tx_type == transaction_type::ONSHORE) ? get_onshore_fee(destinations, unlock_time - current_height - 1, hf_version) :
    (tx_type == transaction_type::XUSD_TO_XASSET) ? get_xusd_to_xasset_fee(destinations, hf_version) :
    (tx_type == transaction_type::XASSET_TO_XUSD) ? get_xasset_to_xusd_fee(destinations, hf_version) : 0;

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      const txin_haven_key &tk0 = boost::get<txin_haven_key>(tx.vin[i0]);
      const txin_haven_key &tk1 = boost::get<txin_haven_key>(tx.vin[i1]);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    tools::apply_permutation(ins_order, [&] (size_t i0, size_t i1) {
      std::swap(tx.vin[i0], tx.vin[i1]);
      std::swap(in_contexts[i0], in_contexts[i1]);
      std::swap(sources[i0], sources[i1]);
    });

    // figure out if we need to make additional tx pubkeys
    size_t num_stdaddresses = 0;
    size_t num_subaddresses = 0;
    account_public_address single_dest_subaddress;
    classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);

    // if this is a single-destination transfer to a subaddress, we set the tx pubkey to R=s*D
    if (num_stdaddresses == 0 && num_subaddresses == 1)
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultKey(rct::pk2rct(single_dest_subaddress.m_spend_public_key), rct::sk2rct(tx_key)));
    }
    else
    {
      txkey_pub = rct::rct2pk(hwdev.scalarmultBase(rct::sk2rct(tx_key)));
    }
    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_pub_key));
    add_tx_pub_key_to_extra(tx, txkey_pub);

    std::vector<crypto::public_key> additional_tx_public_keys;

    // we don't need to include additional tx keys if:
    //   - all the destinations are standard addresses
    //   - there's only one destination which is a subaddress
    bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
    if (need_additional_txkeys)
      CHECK_AND_ASSERT_MES(destinations.size() == additional_tx_keys.size(), false, "Wrong amount of additional tx keys");

    uint64_t summary_outs_money = 0;
    //fill outputs
    size_t output_index = 0;
    uint64_t summary_outs_slippage = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      CHECK_AND_ASSERT_MES(dst_entr.dest_amount > 0 || tx.version > 1, false, "Destination with wrong amount: " << dst_entr.dest_amount);
      crypto::public_key out_eph_public_key;
      crypto::view_tag view_tag;

      // Sum all the slippage across the outputs
      summary_outs_slippage += dst_entr.slippage;
      
      hwdev.generate_output_ephemeral_keys(tx.version,sender_account_keys, txkey_pub, tx_key,
                                           dst_entr, change_addr, output_index,
                                           need_additional_txkeys, additional_tx_keys,
                                           additional_tx_public_keys, amount_keys, out_eph_public_key,
                                           use_view_tags, view_tag);

      // dont lock the change dests
      uint64_t u_time = tx.unlock_time;
      if (hf_version >= HF_VERSION_SLIPPAGE && dst_entr.is_collateral) {
        if (nettype == TESTNET || nettype == STAGENET) {
          u_time = HF23_COLLATERAL_LOCK_BLOCKS_TESTNET + current_height + 1;
        } else {
          u_time = HF23_COLLATERAL_LOCK_BLOCKS + current_height + 1;
        }
      } else if (hf_version >= HF_VERSION_USE_COLLATERAL_V2 && dst_entr.is_collateral) {
        if (nettype == TESTNET || nettype == STAGENET) {
          u_time = HF21_COLLATERAL_LOCK_BLOCKS_TESTNET + current_height + 1;
        } else {
          u_time = HF21_COLLATERAL_LOCK_BLOCKS + current_height + 1;
        }
      } else if (hf_version >= HF_VERSION_USE_COLLATERAL && tx_type == transaction_type::ONSHORE && dst_entr.is_collateral_change) {
        u_time = 0;
      } else {
        if (dst_entr.dest_asset_type == source_asset) {
          u_time = 0;
        }
      }

      tx_out out;
      cryptonote::set_tx_out(dst_entr.dest_amount, dst_entr.dest_asset_type, u_time, dst_entr.is_collateral, dst_entr.is_collateral_change, out_eph_public_key, use_view_tags, view_tag, out);
      
      tx.vout.push_back(out);
      output_index++;
      summary_outs_money += (dst_entr.is_collateral || dst_entr.is_collateral_change) ? 0 : dst_entr.amount + dst_entr.slippage;

      if (source_asset != dest_asset) {
        if (dst_entr.dest_asset_type == dest_asset && !dst_entr.is_collateral && !dst_entr.is_collateral_change) {
          tx.amount_minted += dst_entr.dest_amount;
          tx.amount_burnt += dst_entr.amount + dst_entr.slippage;
        }
      }
    }
    CHECK_AND_ASSERT_MES(additional_tx_public_keys.size() == additional_tx_keys.size(), false, "Internal error creating additional public keys");

    remove_field_from_tx_extra(tx.extra, typeid(tx_extra_additional_pub_keys));

    LOG_PRINT_L2("tx pubkey: " << txkey_pub);
    if (need_additional_txkeys)
    {
      LOG_PRINT_L2("additional tx pubkeys: ");
      for (size_t i = 0; i < additional_tx_public_keys.size(); ++i)
        LOG_PRINT_L2(additional_tx_public_keys[i]);
      add_additional_tx_pub_keys_to_extra(tx.extra, additional_tx_public_keys);
    }

    if (!sort_tx_extra(tx.extra, tx.extra))
      return false;

    CHECK_AND_ASSERT_MES(tx.extra.size() <= MAX_TX_EXTRA_SIZE, false, "TX extra size (" << tx.extra.size() << ") is greater than max allowed (" << MAX_TX_EXTRA_SIZE << ")");

    //check money
    if(summary_outs_money > summary_inputs_money )
    {
      LOG_ERROR("Transaction inputs money ("<< summary_inputs_money << ") less than outputs money (" << summary_outs_money << ")");
      return false;
    }
    
    // check col money
    uint64_t col_in_money = 0, col_out_money = 0;
    if (hf_version >= HF_VERSION_USE_COLLATERAL)
    { 
      for(const tx_source_entry& src_entr:  sources)
        if (src_entr.asset_type == dest_asset)
          col_in_money += src_entr.amount;
      for(const tx_destination_entry& dst_entr: destinations)
        if (dst_entr.is_collateral || dst_entr.is_collateral_change)
          col_out_money += dst_entr.amount;

      if((col_out_money != col_in_money) && tx_type == transaction_type::ONSHORE)
      {
        LOG_ERROR("Transaction collateral inputs money ("<< col_in_money << ") is not equal to outputs money (" << col_out_money << ")");
        return false;
      }
    }

    // Add 80% of the conversion fee to the amount burnt
    if (hf_version >= HF_VERSION_XASSET_FEES_V2 && (tx_type == transaction_type::XUSD_TO_XASSET || tx_type == transaction_type::XASSET_TO_XUSD)) {
      if (hf_version < HF_VERSION_USE_COLLATERAL) {
        tx.amount_burnt += (offshore_fee * 4) / 5;
      }
    }

    // check for watch only wallet
    bool zero_secret_key = true;
    for (size_t i = 0; i < sizeof(sender_account_keys.m_spend_secret_key); ++i)
      zero_secret_key &= (sender_account_keys.m_spend_secret_key.data[i] == 0);
    if (zero_secret_key)
    {
      MDEBUG("Null secret key, skipping signatures");
    }

    if (tx.version == 1)
    {
      //generate ring signatures
      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash);

      std::stringstream ss_ring_s;
      size_t i = 0;
      for(const tx_source_entry& src_entr:  sources)
      {
        ss_ring_s << "pub_keys:" << ENDL;
        std::vector<const crypto::public_key*> keys_ptrs;
        std::vector<crypto::public_key> keys(src_entr.outputs.size());
        size_t ii = 0;
        for(const tx_source_entry::output_entry& o: src_entr.outputs)
        {
          keys[ii] = rct2pk(o.second.dest);
          keys_ptrs.push_back(&keys[ii]);
          ss_ring_s << o.second.dest << ENDL;
          ++ii;
        }

        tx.signatures.push_back(std::vector<crypto::signature>());
        std::vector<crypto::signature>& sigs = tx.signatures.back();
        sigs.resize(src_entr.outputs.size());
        if (!zero_secret_key)
          crypto::generate_ring_signature(tx_prefix_hash, boost::get<txin_haven_key>(tx.vin[i]).k_image, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());
        ss_ring_s << "signatures:" << ENDL;
        std::for_each(sigs.begin(), sigs.end(), [&](const crypto::signature& s){ss_ring_s << s << ENDL;});
        ss_ring_s << "prefix_hash:" << tx_prefix_hash << ENDL << "in_ephemeral_key: " << in_contexts[i].in_ephemeral.sec << ENDL << "real_output: " << src_entr.real_output << ENDL;
        i++;
      }

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL << ss_ring_s.str());
      }
    else
    {
      size_t n_total_outs = sources[0].outputs.size(); // only for non-simple rct

      // the non-simple version is slightly smaller, but assumes all real inputs
      // are on the same index, so can only be used if there just one ring.
      bool use_simple_rct = sources.size() > 1 || rct_config.range_proof_type != rct::RangeProofBorromean;

      if (!use_simple_rct)
      {
        // non simple ringct requires all real inputs to be at the same index for all inputs
        for(const tx_source_entry& src_entr:  sources)
        {
          if(src_entr.real_output != sources.begin()->real_output)
          {
            LOG_ERROR("All inputs must have the same index for non-simple ringct");
            return false;
          }
        }

        // enforce same mixin for all outputs
        for (size_t i = 1; i < sources.size(); ++i) {
          if (n_total_outs != sources[i].outputs.size()) {
            LOG_ERROR("Non-simple ringct transaction has varying ring size");
            return false;
          }
        }
      }

      uint64_t amount_in = 0, amount_out = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
      rct::keyV destinations;
      std::vector<uint64_t> inamounts, outamounts;
      std::vector<size_t> inamounts_col_indices;
      std::map<size_t, std::pair<std::string, std::pair<bool,bool>>> outamounts_features;
      std::vector<unsigned int> index;
      for (size_t i = 0; i < sources.size(); ++i)
      {
        if (sources[i].asset_type == "XHV" && tx_type == transaction_type::ONSHORE && hf_version >= HF_VERSION_USE_COLLATERAL) {
          inamounts_col_indices.push_back(i);
        }

        rct::ctkey ctkey;
        if (sources[i].asset_type == source_asset)
          amount_in += sources[i].amount;
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
      {
        crypto::public_key output_public_key;
        bool ok = cryptonote::get_output_public_key(tx.vout[i], output_public_key);
        if (!ok) {
          LOG_ERROR("failed to get output public key for tx.vout[" << i << "]");
          return false;
        }
        std::string output_asset_type;
        ok = cryptonote::get_output_asset_type(tx.vout[i], output_asset_type);
        if (!ok) {
          LOG_ERROR("failed to get output public key for tx.vout[" << i << "]");
          return false;
        }        
        bool is_collateral = false;
        bool is_collateral_change = false;
        ok = cryptonote::is_output_collateral(tx.vout[i], is_collateral, is_collateral_change);
        if (!ok) {
          LOG_ERROR("failed to get is_collateral for tx.vout[" << i << "]");
          return false;
        }        
        destinations.push_back(rct::pk2rct(output_public_key));
        outamounts.push_back(tx.vout[i].amount);
        outamounts_features[i] = std::pair<std::string, std::pair<bool, bool>>(output_asset_type,{is_collateral,is_collateral_change});
        amount_out += tx.vout[i].amount;
      }

      if (use_simple_rct)
      {
        // mixRing indexing is done the other way round for simple
        for (size_t i = 0; i < sources.size(); ++i)
        {
          mixRing[i].resize(sources[i].outputs.size());
          for (size_t n = 0; n < sources[i].outputs.size(); ++n)
          {
            mixRing[i][n] = sources[i].outputs[n].second;
          }
        }
      }
      else
      {
        for (size_t i = 0; i < n_total_outs; ++i) // same index assumption
        {
          mixRing[i].resize(sources.size());
          for (size_t n = 0; n < sources.size(); ++n)
          {
            mixRing[i][n] = sources[n].outputs[i].second;
          }
        }
      }

      // fee
      if (!use_simple_rct && amount_in > amount_out)
        outamounts.push_back(amount_in - amount_out);
      else
        fee = summary_inputs_money - summary_outs_money - offshore_fee;
      
      // since the col ins are added to the summary_inputs_money above for offshores, subtract it.
      if (tx_type == transaction_type::OFFSHORE && hf_version >= HF_VERSION_USE_COLLATERAL) {
        fee -= col_out_money;
      }

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct)
          boost::get<txin_haven_key>(tx.vin[i]).amount = 0;
      }
      for (size_t i = 0; i < tx.vout.size(); ++i)
        tx.vout[i].amount = 0;

      // NEAC: Convert the fees for conversions to XHV
      uint64_t conversion_rate = COIN;
      if (hf_version >= HF_VERSION_CONVERSION_FEES_IN_XHV) {

        // Convert TX fee to XHV
        uint64_t tx_fee_check = 0;
        if (tx_type == transaction_type::OFFSHORE || tx_type == transaction_type::ONSHORE || tx_type == transaction_type::XUSD_TO_XASSET || tx_type == transaction_type::XASSET_TO_XUSD) {
          // Get a conversion rate to verify the TX fee
          uint64_t inverse_conversion_rate = COIN;
          if (!cryptonote::get_conversion_rate(pr, "XHV", source_asset, inverse_conversion_rate)) {
            LOG_ERROR("Failed to get conversion rate for fees - aborting");
            return false;
          }
          if (!cryptonote::get_converted_amount(inverse_conversion_rate, fee_xhv, tx_fee_check)) {
            LOG_ERROR("Failed to get converted TX fee amount - aborting");
            return false;
          }
          if (tx_fee_check != fee) {
            LOG_ERROR("Converted TX fee amount is incorrect: got " << print_money(tx_fee_check) << " " << source_asset << ", expected " << print_money(fee) << " - aborting");
            return false;
          }
          fee = fee_xhv;

          // Convert offshore fee to XHV
          uint64_t offshore_fee_xhv = 0;
          if (!cryptonote::get_conversion_rate(pr, source_asset, "XHV", conversion_rate)) {
            LOG_ERROR("Failed to get conversion rate for fees - aborting");
            return false;
          }
          if (!cryptonote::get_converted_amount(conversion_rate, offshore_fee, offshore_fee_xhv)) {
            LOG_ERROR("Failed to get converted conversion fee amount - aborting");
            return false;
          }
          offshore_fee = offshore_fee_xhv;
        }
      }

      // NEAC: get conversion rate - this replaces the direct use of the Pricing Record to avoid invert() scaling
      conversion_rate = COIN;
      if (!cryptonote::get_conversion_rate(pr, source_asset, dest_asset, conversion_rate)) {
        LOG_ERROR("Failed to get conversion rate for output - aborting");
        return false;
      }
      
      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
      rct::ctkeyV outSk;
      if (use_simple_rct)
        tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destinations, tx_type, source_asset, inamounts, inamounts_col_indices, outamounts, outamounts_features, fee, offshore_fee, onshore_col_amount, mixRing, amount_keys, index, outSk, tx.version, pr, conversion_rate, hf_version, rct_config, hwdev);
      else
        tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, destinations, outamounts, mixRing, amount_keys, sources[0].real_output, outSk, rct_config, hwdev); // same index assumption
      memwipe(inSk.data(), inSk.size() * sizeof(rct::ctkey));

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(
    const std::string& source_asset,
    const std::string& dest_asset,
    const offshore::pricing_record& pr,
    const account_keys& sender_account_keys,
    const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses,
    std::vector<tx_source_entry>& sources,
    std::vector<tx_destination_entry>& destinations,
    const boost::optional<cryptonote::account_public_address>& change_addr,
    const std::vector<uint8_t> &extra,
    transaction& tx,
    const uint64_t unlock_time,
    const uint8_t hf_version,
    const uint64_t current_height,
    const uint64_t onshore_col_amount,
    const uint64_t fee_xhv,
    crypto::secret_key &tx_key,
    std::vector<crypto::secret_key> &additional_tx_keys,
    bool rct,
    const rct::RCTConfig &rct_config,
    bool use_view_tags,
    network_type nettype
  ){
    hw::device &hwdev = sender_account_keys.get_device();
    hwdev.open_tx(tx_key);
    try {
      // figure out if we need to make additional tx pubkeys
      size_t num_stdaddresses = 0;
      size_t num_subaddresses = 0;
      account_public_address single_dest_subaddress;
      classify_addresses(destinations, change_addr, num_stdaddresses, num_subaddresses, single_dest_subaddress);
      bool need_additional_txkeys = num_subaddresses > 0 && (num_stdaddresses > 0 || num_subaddresses > 1);
      if (need_additional_txkeys)
      {
        additional_tx_keys.clear();
        for (size_t i = 0; i < destinations.size(); ++i)
        {
          additional_tx_keys.push_back(keypair::generate(sender_account_keys.get_device()).sec);
        }
      }

      bool shuffle_outs = true;
      bool r = construct_tx_with_tx_key(
        source_asset,
        dest_asset,
        pr,
        sender_account_keys,
        subaddresses,
        sources,
        destinations,
        change_addr,
        extra,
        tx,
        unlock_time,
        hf_version,
        current_height,
        onshore_col_amount,
        fee_xhv,
        tx_key,
        additional_tx_keys,
        rct,
        rct_config,
        shuffle_outs,
        use_view_tags,
        nettype
      );
      hwdev.close_tx();
      return r;
    } catch(...) {
      hwdev.close_tx();
      throw;
    }
  }
  //---------------------------------------------------------------
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
     std::vector<tx_destination_entry> destinations_copy = destinations;
     return construct_tx_and_get_tx_key("XHV", "XHV", offshore::pricing_record(), sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, 1, 1, 0, 0, tx_key, additional_tx_keys, false, { rct::RangeProofBorromean, 0});
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    )
  {
    //genesis block
    bl = {};

    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, const crypto::hash *seed_hash, unsigned int threads, crypto::hash &hash){
      return cryptonote::get_block_longhash(NULL, b, hash, height, seed_hash, threads);
    }, bl, 1, 0, NULL);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  void get_altblock_longhash(const block& b, crypto::hash& res, const crypto::hash& seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    rx_slow_hash(seed_hash.data, bd.data(), bd.size(), res.data);
  }

  bool get_block_longhash(const Blockchain *pbc, const blobdata& bd, crypto::hash& res, const uint64_t height, const int major_version, const crypto::hash *seed_hash, const int miners)
  {
    cn_pow_hash_v3 ctx;
    if(major_version >= CRYPTONOTE_V3_POW_BLOCK_VERSION)
    {
      ctx.hash(bd.data(), bd.size(), res.data);
    }
    else if(major_version == CRYPTONOTE_V2_POW_BLOCK_VERSION)
    {
      cn_pow_hash_v2 ctx_v2 = cn_pow_hash_v2::make_borrowed_v2(ctx);
      ctx_v2.hash(bd.data(), bd.size(), res.data);
    }
    else
    {
      cn_pow_hash_v1 ctx_v1 = cn_pow_hash_v1::make_borrowed_v1(ctx);
      ctx_v1.hash(bd.data(), bd.size(), res.data);
    }
    return true;
    /*
    // block 202612 bug workaround
    if (height == 202612)
    {
      static const std::string longhash_202612 = "84f64766475d51837ac9efbef1926486e58563c95a19fef4aec3254f03000000";
      epee::string_tools::hex_to_pod(longhash_202612, res);
      return true;
    }
    if (major_version >= RX_BLOCK_VERSION)
    {
      crypto::hash hash;
      if (pbc != NULL)
      {
        const uint64_t seed_height = rx_seedheight(height);
        hash = seed_hash ? *seed_hash : pbc->get_pending_block_id_by_height(seed_height);
      } else
      {
        memset(&hash, 0, sizeof(hash));  // only happens when generating genesis block
      }
      rx_slow_hash(hash.data, bd.data(), bd.size(), res.data);
    } else {
      const int pow_variant = major_version >= 7 ? major_version - 6 : 0;
      crypto::cn_slow_hash(bd.data(), bd.size(), res, pow_variant, height);
    }
    return true;
    */
  }

  bool get_block_longhash(const Blockchain *pbc, const block& b, crypto::hash& res, const uint64_t height, const crypto::hash *seed_hash, const int miners)
  {
    blobdata bd = get_block_hashing_blob(b);
	return get_block_longhash(pbc, bd, res, height, b.major_version, seed_hash, miners);
  }

  crypto::hash get_block_longhash(const Blockchain *pbc, const block& b, const uint64_t height, const crypto::hash *seed_hash, const int miners)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(pbc, b, p, height, seed_hash, miners);
    return p;
  }
}
