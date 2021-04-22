// Copyright (c) 2014-2019, The Monero Project
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

  uint64_t get_governance_reward(uint64_t height, uint64_t base_reward)
  {
    return base_reward / 20;
  }

  bool get_deterministic_output_key(const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key)
  {

    crypto::key_derivation derivation = AUTO_VAL_INIT(derivation);
    bool r = crypto::generate_key_derivation(address.m_view_public_key, tx_key.sec, derivation);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << address.m_view_public_key << ", " << tx_key.sec << ")");

    r = crypto::derive_public_key(derivation, output_index, address.m_spend_public_key, output_key);
    CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key(" << derivation << ", "<< address.m_spend_public_key << ")");

    return true;
  }

  bool validate_governance_reward_key(uint64_t height, const std::string& governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, cryptonote::network_type nettype)
  {
    keypair gov_key = get_deterministic_keypair_from_height(height);

    cryptonote::address_parse_info governance_wallet_address;

    if (nettype == TESTNET) {
      cryptonote::get_account_address_from_str(governance_wallet_address, TESTNET, governance_wallet_address_str);
    } else if (nettype == STAGENET) {
      cryptonote::get_account_address_from_str(governance_wallet_address, STAGENET, governance_wallet_address_str);
    } else {
      cryptonote::get_account_address_from_str(governance_wallet_address, MAINNET, governance_wallet_address_str);
    }

    crypto::public_key correct_key;

    if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, output_index, correct_key))
    {
      MERROR("Failed to generate deterministic output key for governance wallet output validation");
      return false;
    }

    return correct_key == output_key;
  }
  
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, std::map<std::string, uint64_t> fee_map,  std::map<std::string, uint64_t> offshore_fee_map, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce, size_t max_outs, uint8_t hard_fork_version, cryptonote::network_type nettype) {
    tx.vin.clear();
    tx.vout.clear();
    tx.extra.clear();

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
    // HERE BE DRAGONS!!!
    // NEAC: need to iterate over the currency maps to output all fees
    //LOG_PRINT_L1("Creating block template: reward " << block_reward <<
    //  ", fee " << fee);
    // LAND AHOY!!!
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

    txout_to_key tk;
    tk.key = out_eph_public_key;

    tx_out out;
    summary_amounts += out.amount = block_reward;
    out.target = tk;
    tx.vout.push_back(out);

    cryptonote::address_parse_info governance_wallet_address;

    if (hard_fork_version >= 3) {
      if (already_generated_coins != 0)
      {
        add_tx_pub_key_to_extra(tx, gov_key.pub);

        if (hard_fork_version >= HF_VERSION_XASSET_FULL) {
          if (nettype == TESTNET) {
            cryptonote::get_account_address_from_str(governance_wallet_address, TESTNET, ::config::testnet::GOVERNANCE_WALLET_ADDRESS_MULTI);
          } else if (nettype == STAGENET) {
	    cryptonote::get_account_address_from_str(governance_wallet_address, STAGENET, ::config::stagenet::GOVERNANCE_WALLET_ADDRESS_MULTI);
          } else {
            cryptonote::get_account_address_from_str(governance_wallet_address, MAINNET, ::config::GOVERNANCE_WALLET_ADDRESS_MULTI_NEW);
          }
        } else if (hard_fork_version >= 4) {
          // shouts to sebseb7
          if (nettype == TESTNET) {
            cryptonote::get_account_address_from_str(governance_wallet_address, TESTNET, ::config::testnet::GOVERNANCE_WALLET_ADDRESS_MULTI);
          } else if (nettype == STAGENET) {
	    cryptonote::get_account_address_from_str(governance_wallet_address, STAGENET, ::config::stagenet::GOVERNANCE_WALLET_ADDRESS_MULTI);
          } else {
            cryptonote::get_account_address_from_str(governance_wallet_address, MAINNET, ::config::GOVERNANCE_WALLET_ADDRESS_MULTI);
          }
        } else {
          if (nettype == TESTNET) {
            cryptonote::get_account_address_from_str(governance_wallet_address, TESTNET, ::config::testnet::GOVERNANCE_WALLET_ADDRESS);
          } else if (nettype == STAGENET) {
	    cryptonote::get_account_address_from_str(governance_wallet_address, STAGENET, ::config::stagenet::GOVERNANCE_WALLET_ADDRESS);
          } else {
            cryptonote::get_account_address_from_str(governance_wallet_address, MAINNET, ::config::GOVERNANCE_WALLET_ADDRESS);
          }
        }

        crypto::public_key out_eph_public_key = AUTO_VAL_INIT(out_eph_public_key);

        if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, 1 /* second output in miner tx */, out_eph_public_key))
        {
          MERROR("Failed to generate deterministic output key for governance wallet output creation");
          return false;
        }

        txout_to_key tk;
        tk.key = out_eph_public_key;

        tx_out out;
        summary_amounts += out.amount = governance_reward;

        if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
          out.amount += offshore_fee_map["XHV"];
        }

        out.target = tk;
        tx.vout.push_back(out);

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

	  // Miner component of the xAsset TX fee
	  r = crypto::derive_public_key(derivation, idx, miner_address.m_spend_public_key, out_eph_public_key);
	  CHECK_AND_ASSERT_MES(r, false, "while creating outs: failed to derive_public_key(" << derivation << ", " << idx << ", "<< miner_address.m_spend_public_key << ")");
	  idx++;

	  if (fee_map_entry.first == "XUSD") {
	    // Offshore TX
	    txout_offshore tk_off;
	    tk_off.key = out_eph_public_key;
      
	    tx_out out_off;
	    out_off.amount = block_reward_xasset;
	    out_off.target = tk_off;
	    tx.vout.push_back(out_off);
	  } else {
	    // xAsset TX
	    txout_xasset tk_off;
	    tk_off.key = out_eph_public_key;
	    tk_off.asset_type = fee_map_entry.first;
      
	    tx_out out_off;
	    out_off.amount = block_reward_xasset;
	    out_off.target = tk_off;
	    tx.vout.push_back(out_off);
	  }

	  crypto::public_key out_eph_public_key_xasset = AUTO_VAL_INIT(out_eph_public_key_xasset);

	  if (!get_deterministic_output_key(governance_wallet_address.address, gov_key, idx /* n'th output in miner tx */, out_eph_public_key_xasset))
	  {
	    MERROR("Failed to generate deterministic output key for governance wallet output creation (2)");
	    return false;
	  }
	  idx++;

	  if (fee_map_entry.first == "XUSD") {
	    // Offshore TX
	    txout_offshore tk_gov;
	    tk_gov.key = out_eph_public_key_xasset;
	    
	    tx_out out_gov;
	    out_gov.amount = governance_reward_xasset;
	    out_gov.target = tk_gov;
	    tx.vout.push_back(out_gov);
	  } else {
	    // xAsset TX
	    txout_xasset tk_gov;
	    tk_gov.key = out_eph_public_key_xasset;
	    tk_gov.asset_type = fee_map_entry.first;
	    
	    tx_out out_gov;
	    out_gov.amount = governance_reward_xasset;
	    out_gov.target = tk_gov;
	    tx.vout.push_back(out_gov);
	  }
	}
      }
    }
    
    if (hard_fork_version >= HF_VERSION_OFFSHORE_FULL) {
      tx.version = CURRENT_TRANSACTION_VERSION;
    } else {
      tx.version = 2;
    }

    //lock
    tx.unlock_time = height + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
    tx.vin.push_back(in);

    tx.invalidate_hashes();

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
      if (i.amount == 0 && i.amount_usd == 0 && i.amount_xasset == 0)
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
  bool get_offshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t current_height) {

    // Calculate the amount being sent
    uint64_t amount = 0;
    for (auto dt: dsts) {
      if (0 == dt.amount) {
	MERROR("No XHV amount specified for destination");
	return false;
      }
      // Filter out the change, which is never converted
      if (dt.amount_usd != 0) {
	amount += dt.amount;
      }
    }

    if (0/*fees_version >= 3*/) {

      // Get the delta
      // abs() implementation for uint64_t's
      uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;
      
      // Work out the priority 
      uint32_t priority =
	(unlock_time >= 7200) ? 1 :
	(unlock_time >= 3600) ? 2 :
	(unlock_time >= 1440) ? 3 :
	4;
     
      // Estimate the fee components
      boost::multiprecision::uint128_t conversion_fee = amount / 500;
      conversion_fee *= priority;
      boost::multiprecision::uint128_t conversion_extra = delta;
      conversion_extra *= amount;
      uint64_t speed_fee = 0;
      uint64_t speculation_fee = 0;
      switch (priority) {
      case 4:
	conversion_extra *= 110;
	conversion_extra /= 100;
	conversion_extra /= pr.unused1;
	conversion_fee += conversion_extra;
	break;
      case 3:
	conversion_extra /= pr.unused1;
	conversion_fee += conversion_extra;
	break;
      case 2:
	conversion_extra *= 75;
	conversion_extra /= 100;
	conversion_extra /= pr.unused1;
	conversion_fee += conversion_extra;
	break;
      case 1:
      default:
	conversion_extra *= 25;
	conversion_extra /= 100;
	conversion_extra /= pr.unused1;
	conversion_fee += conversion_extra;
	break;
      }

      // Calculate the speed fee and speculation fee
      if (sources.size() == 0) {
	// Best-case estimates for now
	speed_fee =
	  (priority == 4) ? amount / 50 :
	  (priority == 3) ? amount / 125 :
	  0;
      } else {

	// Take a copy of the sources, so we can sort by age
	auto sources_copy = sources;
	std::sort(sources_copy.begin(), sources_copy.end(),
		  [](const tx_source_entry &a, const tx_source_entry &b) { return a.height < b.height; });
      
	// Determine the accurate speed fee and speculation_fee
	if (priority >= 3) {
	  uint64_t running_total = 0;
	  uint64_t target_total = amount;// - ((dsts.back().amount > 0) ? dsts.back().amount : dsts.back().amount_usd);
	  for (auto src: sources_copy) {
	    uint64_t age = current_height - src.height;
	    uint64_t src_amount = src.amount;
	    if (running_total + src_amount <= target_total) {
	      if (age < (30*24*30)) {
		speed_fee += (priority == 4) ? src_amount / 20 : src_amount / 50;
	      } else {
		speed_fee += (priority == 4) ? src_amount / 50 : src_amount / 125;
	      }
	    } else {
	      // Recalculate the src_amount to finish off the TX
	      src_amount = target_total - running_total;
	      if (age < (30*24*30)) {
		speed_fee += (priority == 4) ? src_amount / 20 : src_amount / 50;
	      } else {
		speed_fee += (priority == 4) ? src_amount / 50 : src_amount / 125;
	      }
	    }
	    // Advance the running total
	    running_total += src_amount;
	  }
	}
      }
    
      // Return the fee
      MINFO("Priority = " << priority << ", spot price = " << print_money((uint64_t)pr.xUSD) << ", MA = " << print_money(pr.unused1));
      MINFO("Conversion fee = " << print_money((uint64_t)conversion_fee) << ", speed fee = " << print_money(speed_fee));
      fee_estimate = (uint64_t)conversion_fee + speed_fee + speculation_fee;
      
    } else if (fees_version >= 2) {

      // The tests have to be written largest unlock_time first, as it is possible to delay the construction of the TX using GDB etc
      // which would otherwise cause the umlock_time to fall through the gaps and give a minimum fee for a short unlock_time.
      // This way, the code is safe, and the fee is always correct.
      fee_estimate =
	(unlock_time >= 5040) ? (amount / 500) :
	(unlock_time >= 1440) ? (amount / 20) :
	(unlock_time >= 720) ? (amount / 10) :
	amount / 5;

    } else {
      // Get the delta
      // abs() implementation for uint64_t's
      uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;
      
      // Estimate the fee
      fee_estimate = delta * exp((M_PI / -1000.0) * (unlock_time - 60) * 1.2) * amount / 1000000000000;
    }
    // Return success
    return true;
  }
  //---------------------------------------------------------------
  bool get_onshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t current_height) {

    // Calculate the amount being sent
    uint64_t amount_usd = 0;
    for (auto dt: dsts) {
      if (0 == dt.amount_usd) {
	MERROR("No USD amount specified for destination");
	return false;
      }
      // Filter out the change, which is never converted
      if (dt.amount != 0) {
	amount_usd += dt.amount_usd;
      }
    }

    if (0/*fees_version >= 3*/) {

      // Get the delta
      // abs() implementation for uint64_t's
      uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;
      
      // Work out the priority 
      uint32_t priority =
	(unlock_time >= 7200) ? 1 :
	(unlock_time >= 3600) ? 2 :
	(unlock_time >= 1440) ? 3 :
	4;
     
      // Estimate the fee components
      boost::multiprecision::uint128_t conversion_fee = amount_usd / 500;
      conversion_fee *= priority;
      boost::multiprecision::uint128_t conversion_extra = delta;
      conversion_extra *= amount_usd;
      uint64_t speed_fee = 0;
      uint64_t speculation_fee = 0;
      switch (priority) {
      case 4:
	conversion_extra *= 110;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      case 3:
	conversion_extra /= 1000000000000;
	conversion_fee += conversion_extra;
	break;
      case 2:
	conversion_extra *= 75;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      case 1:
      default:
	conversion_extra *= 25;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      }

      // Calculate the speed fee and speculation fee
      if (sources.size() == 0) {
	// Best-case estimates for now
	speed_fee =
	  (priority == 4) ? amount_usd / 50 :
	  (priority == 3) ? amount_usd / 125 :
	  0;
      } else {

	// Take a copy of the sources, so we can sort by age
	auto sources_copy = sources;
	std::sort(sources_copy.begin(), sources_copy.end(),
		  [](const tx_source_entry &a, const tx_source_entry &b) { return a.height < b.height; });
      
	// Create a vector of block heights to obtain pricing records for
	std::vector<uint64_t> heights;
      
	// Determine the accurate speed fee and speculation_fee
	if (priority >= 3) {
	  uint64_t running_total = 0;
	  uint64_t target_total = amount_usd;// - ((dsts.back().amount > 0) ? dsts.back().amount : dsts.back().amount_usd);
	  for (auto src: sources_copy) {
	    heights.push_back(src.height);
	    uint64_t age = current_height - src.height;
	    uint64_t src_amount = src.amount;
	    if (running_total + src_amount <= target_total) {
	      if (age < (30*24*30)) {
		speed_fee += (priority == 4) ? src_amount / 20 : src_amount / 50;
	      } else {
		speed_fee += (priority == 4) ? src_amount / 50 : src_amount / 125;
	      }
	    } else {
	      // Recalculate the src_amount to finish off the TX
	      src_amount = target_total - running_total;
	      if (age < (30*24*30)) {
		speed_fee += (priority == 4) ? src_amount / 20 : src_amount / 50;
	      } else {
		speed_fee += (priority == 4) ? src_amount / 50 : src_amount / 125;
	      }
	    }
	    // Advance the running total
	    running_total += src_amount;
	  }
	}
	
	// Only bother if we have some heights to use
	if (heights.size()) {

	  int i=0;
	  for (auto src: sources_copy) {

	    // Only charge fees for first-generation offshore inputs
	    if (!src.first_generation_input) {
	      MINFO("Input was not created using XHV - no speculation fee applied");
	      continue;
	    }
	    if (pr.unused1 < src.pr.unused1) {
	      // current exchange rate less than when the input was created - how old is it?

	      boost::multiprecision::uint128_t ma_diff = (src.pr.unused1 - pr.unused1);
	      ma_diff *= src.amount;
	      ma_diff /= 1000000000000;
	      
	      // Check the age of the input
	      uint64_t age = current_height - src.height;
	      uint64_t fee_addition = 0;
	      if (priority == 4) {
		if (age < (30 * 24)) {
		  // Calculate the speculation fee
		  fee_addition = (uint64_t)ma_diff / 2;
		} else if (age < (30 * 48)) {
		  // Calculate the speculation fee
		  fee_addition = ((uint64_t)ma_diff * 4) / 10;
		} else if (age < (30 * 120)) {
		  // Calculate the speculation fee
		  fee_addition = (uint64_t)ma_diff / 10;
		}
	      } else if (priority == 3) {
		if (age < (30 * 120)) {
		  // Calculate the speculation fee
		  fee_addition = (uint64_t)ma_diff / 10;
		}
	      }
	      MINFO("Input created using XHV - amount = " << print_money(src.amount) << ", age = " << age);
	      MINFO("Original MA = " << print_money(src.pr.unused1) << ", speculation fee " << print_money(fee_addition) << " applied");
	      speculation_fee += fee_addition;
	    }
	  }
	}
      }
    
      // Return the fee
      MINFO("Priority = " << priority << ", spot price = " << print_money((uint64_t)pr.xUSD) << ", MA = " << print_money(pr.unused1));
      MINFO("Conversion fee = " << print_money((uint64_t)conversion_fee) << ", speed fee = " << print_money(speed_fee) << ", speculation fee = " << print_money(speculation_fee));
      fee_estimate = (uint64_t)conversion_fee + speed_fee + speculation_fee;
      
    } else if (fees_version >= 2) {

      // The tests have to be written largest unlock_time first, as it is possible to delay the construction of the TX using GDB etc
      // which would otherwise cause the umlock_time to fall through the gaps and give a minimum fee for a short unlock_time.
      // This way, the code is safe, and the fee is always correct.
      fee_estimate =
	(unlock_time >= 5040) ? (amount_usd / 500) :
	(unlock_time >= 1440) ? (amount_usd / 20) :
	(unlock_time >= 720) ? (amount_usd / 10) :
	amount_usd / 5;

    } else {
      // Get the delta
      // abs() implementation for uint64_t's
      uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;
      
      // Estimate the fee
      fee_estimate = delta * exp((M_PI / -1000.0) * (unlock_time - 60) * 1.2) * amount_usd / 1000000000000;
    }
    
    // Return success
    return true;
  }
  //---------------------------------------------------------------
  bool get_offshore_to_offshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t current_height) {

    // Calculate the amount being sent
    auto dsts_copy = dsts;
    // Exclude the change
    dsts_copy.pop_back();
    uint64_t amount_usd = 0;
    for (auto dt: dsts_copy) {
      if (0 == dt.amount_usd) {
	MERROR("No USD amount specified for destination");
	return false;
      }
      amount_usd += dt.amount_usd;
    }

    if (0/*fees_version >= 3*/) {

      // Get the delta
      // abs() implementation for uint64_t's
      uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;
      
      // Work out the priority 
      uint32_t priority =
	(unlock_time >= 7200) ? 1 :
	(unlock_time >= 3600) ? 2 :
	(unlock_time >= 1440) ? 3 :
	4;

      // NEAC: temporarily force the priority to 4 because we don't use it for faster unlocks yet
      priority = 4;
     
      // Estimate the fee components
      boost::multiprecision::uint128_t conversion_fee = amount_usd / 500;
      conversion_fee *= priority;
      boost::multiprecision::uint128_t conversion_extra = delta;
      conversion_extra *= amount_usd;
      uint64_t speed_fee = 0;
      uint64_t speculation_fee = 0;
      switch (priority) {
      case 4:
	conversion_extra *= 110;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      case 3:
	conversion_extra /= 1000000000000;
	conversion_fee += conversion_extra;
	break;
      case 2:
	conversion_extra *= 75;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      case 1:
      default:
	conversion_extra *= 25;
	conversion_extra /= (100 * 1000000000000);
	conversion_fee += conversion_extra;
	break;
      }

      // Calculate the speed fee and speculation fee
      if (sources.size() == 0) {
	// Best-case estimates for now
	speed_fee =
	  (priority == 4) ? amount_usd / 50 :
	  (priority == 3) ? amount_usd / 125 :
	  0;
      } else {

	// Take a copy of the sources, so we can sort by age
	auto sources_copy = sources;
	std::sort(sources_copy.begin(), sources_copy.end(),
		  [](const tx_source_entry &a, const tx_source_entry &b) { return a.height < b.height; });
      
	for (auto src: sources_copy) {

	  // Only charge fees for first-generation offshore inputs
	  if (!src.first_generation_input) {
	    MINFO("Input was not created using XHV - no speculation fee applied");
	    continue;
	  }
	  if (pr.unused1 < src.pr.unused1) {
	    // current exchange rate less than when the input was created - how old is it?

	    boost::multiprecision::uint128_t ma_diff = (src.pr.unused1 - pr.unused1);
	    ma_diff *= src.amount;
	    ma_diff /= 1000000000000;
	      
	    // Check the age of the input
	    uint64_t age = current_height - src.height;
	    uint64_t fee_addition = 0;
	    if (priority == 4) {
	      if (age < (30 * 24)) {
		// Calculate the speculation fee
		fee_addition = (uint64_t)ma_diff / 2;
	      } else if (age < (30 * 48)) {
		// Calculate the speculation fee
		fee_addition = ((uint64_t)ma_diff * 4) / 10;
	      } else if (age < (30 * 120)) {
		// Calculate the speculation fee
		fee_addition = (uint64_t)ma_diff / 10;
	      }
	    } else if (priority == 3) {
	      if (age < (30 * 120)) {
		// Calculate the speculation fee
		fee_addition = (uint64_t)ma_diff / 10;
	      }
	    }
	    MINFO("Input created using XHV - amount = " << print_money(src.amount) << ", age = " << age);
	    MINFO("Original MA = " << print_money(src.pr.unused1) << ", speculation fee " << print_money(fee_addition) << " applied");
	    speculation_fee += fee_addition;
	  }
	}
      }
    
      // Return the fee
      MINFO("Priority = " << priority << ", spot price = " << print_money((uint64_t)pr.xUSD) << ", MA = " << print_money(pr.unused1));
      MINFO("Speculation fee = " << print_money(speculation_fee));
      fee_estimate = speculation_fee;
      
    } else {

      // Only conventional TX fees prior to fees v3
      fee_estimate = 0;
    }
    
    // Return success
    return true;
  }
  //---------------------------------------------------------------
  bool get_xasset_to_xusd_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height) {

    // Calculate the amount being sent
    auto dsts_copy = dsts;
    // Exclude the change
    dsts_copy.pop_back();
    uint64_t amount_xasset = 0;
    for (auto dt: dsts_copy) {
      if (0 == dt.amount_xasset) {
	MERROR("No xAsset amount specified for destination");
	return false;
      }
      amount_xasset += dt.amount_xasset;
    }

    // Calculate 0.3% of the total being sent
    fee_estimate = (amount_xasset * 3) / 1000;

    // Return success
    return true;
  }
  //---------------------------------------------------------------
  bool get_xusd_to_xasset_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height) {

    // Calculate the amount being sent
    auto dsts_copy = dsts;
    // Exclude the change
    dsts_copy.pop_back();
    uint64_t amount_usd = 0;
    for (auto dt: dsts_copy) {
      if (0 == dt.amount_usd) {
	MERROR("No USD amount specified for destination");
	return false;
      }
      amount_usd += dt.amount_usd;
    }

    // Calculate 0.3% of the total being sent
    fee_estimate = (amount_usd * 3) / 1000;

    // Return success
    return true;
  }

  /*
    Returns the input and output asset types for a given tx.
  */
  bool get_tx_asset_types(const transaction& tx, std::string& source, std::string& destination) {

    // Clear the source
    source = "";
    for (int i=0; i<tx.vin.size(); i++) {
      if ((tx.vin[i].type() == typeid(txin_to_key)) ||
	  (tx.vin[i].type() == typeid(txin_gen))) {
	source = "XHV";
      } else if (tx.vin[i].type() == typeid(txin_offshore)) {
	source = "XUSD";
      } else if (tx.vin[i].type() == typeid(txin_onshore)) {
	source = "XUSD";
      } else if (tx.vin[i].type() == typeid(txin_xasset)) {
	source = boost::get<txin_xasset>(tx.vin[0]).asset_type;
      } else {
	continue;
      }
    }

    // Clear the destination
    destination = "";
    for (const auto &out: tx.vout) {
      if (out.target.type() == typeid(txout_to_key)) {
        destination = "XHV";
      } else if (out.target.type() == typeid(txout_offshore)) {
        destination = "XUSD";
      } else if (out.target.type() == typeid(txout_xasset)) {
        destination = boost::get<txout_xasset>(out.target).asset_type;
      } else {
	continue;
      }
      // if we get the a destination different from source, that means we get what we want.
      // if source and destination is the same we won't break early.
      if (source != destination) {
        break;
      }
    }

    // check both strSource and strDest are supported.
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), source) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Source Asset type " << source << " is not supported! Rejecting..");
      return false;
    }
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), destination) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Destination Asset type " << destination << " is not supported! Rejecting..");
      return false;
    }

    return true;
  }

  //---------------------------------------------------------------
  bool get_tx_type(const std::string& source, const std::string& destination, bool& offshore, bool& onshore, bool& offshore_transfer, bool& xusd_to_xasset, bool& xasset_to_xusd, bool& xasset_transfer) {

    // Clear all the flags
    offshore = onshore = offshore_transfer = xusd_to_xasset = xasset_to_xusd = xasset_transfer = false;

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
    if (source != "XHV" || destination != "XHV") {
      if (source == "XHV") {
	offshore = true;
      } else if (destination == "XHV") {
	onshore = true;
      } else if ((source == "XUSD") && (destination == "XUSD")) {
	offshore_transfer = true;
      } else if ((source != "XUSD") && (destination != "XUSD")) {
	xasset_transfer = true;
      } else if (source == "XUSD") {
	xusd_to_xasset = true;
      } else {
	xasset_to_xusd = true;
      }
    }

    // Return success to caller
    return true;
  }

  //---------------------------------------------------------------
  bool construct_tx_with_tx_key(
    const account_keys& sender_account_keys, 
    const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, 
    std::vector<tx_source_entry>& sources, 
    std::vector<tx_destination_entry>& destinations, 
    const boost::optional<cryptonote::account_public_address>& change_addr, 
    const std::vector<uint8_t> &extra, 
    transaction& tx, uint64_t unlock_time, 
    const crypto::secret_key &tx_key, 
    const std::vector<crypto::secret_key> &additional_tx_keys, 
    uint64_t current_height, 
    offshore::pricing_record pr, 
    uint32_t fees_version, 
    bool use_offshore_tx_version, 
    bool rct, 
    const rct::RCTConfig &rct_config, 
    rct::multisig_out *msout, 
    bool shuffle_outs
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
    if (msout)
    {
      msout->c.clear();
    }

    tx.version = use_offshore_tx_version ? CURRENT_TRANSACTION_VERSION : rct ? 2 : 1;
    tx.unlock_time = unlock_time;

    bool bOffshoreTx = false;
    tx_extra_offshore offshore_data;
    if (extra.size()) {
      // Check to see if this is an offshore tx
      bOffshoreTx = get_offshore_from_tx_extra(extra, offshore_data);
    }

    tx.extra = extra;
    crypto::public_key txkey_pub;

    bool offshore = false;
    bool onshore = false;
    bool offshore_transfer = false;
    bool xasset_transfer = false;
    bool xasset_to_xusd = false;
    bool xusd_to_xasset = false;
    std::string strSource = "XHV"; // Default value is needed for non-offshore TXs
    std::string strDest = "XHV"; // Default value is needed for non-offshore TXs
    if (bOffshoreTx) {
      int pos = offshore_data.data.find("-");
      if (pos != std::string::npos) {
        // New xAsset-style of offshore_data
        strSource = offshore_data.data.substr(0,pos);
        strDest = offshore_data.data.substr(pos+1);
        if (strSource == "XHV") {
          offshore = true;
        } else if (strDest == "XHV") {
          onshore = true;
        } else if ((strSource == "XUSD") && (strDest == "XUSD")) {
          offshore_transfer = true;
        } else if ((strSource != "XUSD") && (strDest != "XUSD")) {
          xasset_transfer = true;
        } else if (strSource == "XUSD") {
          xusd_to_xasset = true;
        } else {
          xasset_to_xusd = true;
        }
      } else {
        // Pre-xAsset format of offshore_data
        // Set the bool flags
        if ((offshore_data.data.at(0) == 'N') && (offshore_data.data.at(1) == 'N')) {
          offshore_transfer = true;
          strSource = "XUSD";
          strDest = "XUSD";
        } else if (offshore_data.data.at(0) == 'N' && offshore_data.data.at(1) == 'A') {
          onshore = true;
          strSource = "XUSD";
          strDest = "XHV";
        } else if (offshore_data.data.at(0) == 'A' && offshore_data.data.at(1) == 'N') {
          offshore = true;
          strSource = "XHV";
          strDest = "XUSD";
        } else {
	  LOG_ERROR("Invalid offshore data");
	  return false;
        }
      }
    }

    // check both strSource and strDest are supported.
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strSource) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Unsupported source asset type " << strSource);
      return false;
    }
    if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strDest) == offshore::ASSET_TYPES.end()) {
      LOG_ERROR("Unsupported destination asset type " << strDest);
      return false;
    }

    const bool use_offshore_outputs = onshore || offshore_transfer || xusd_to_xasset;
    const bool use_xasset_outputs = xasset_transfer || xasset_to_xusd;

    if (bOffshoreTx) {
      if (offshore || onshore || xasset_to_xusd || xusd_to_xasset) {
        tx.pricing_record_height = current_height;
      } else {
        tx.pricing_record_height = 0;
      }
      tx.offshore_data.assign(offshore_data.data.begin(), offshore_data.data.end());
    }

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

    uint64_t summary_inputs_money = 0, summary_inputs_money_usd = 0, summary_inputs_money_xasset = 0;
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

      if (src_entr.asset_type == "XHV") {
        summary_inputs_money += src_entr.amount;
      } else if (src_entr.asset_type == "XUSD") {
        summary_inputs_money_usd += src_entr.amount;
      } else {
        summary_inputs_money_xasset += src_entr.amount;
      }
      
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

      //check that derivated key is equal with real output key (if non multisig)
      if(!msout && !(in_ephemeral.pub == src_entr.outputs[src_entr.real_output].second.dest) )
      {
        LOG_ERROR("derived public key mismatch with output public key at index " << idx << ", real out " << src_entr.real_output << "! "<< ENDL << "derived_key:"
          << string_tools::pod_to_hex(in_ephemeral.pub) << ENDL << "real output_public_key:"
          << string_tools::pod_to_hex(src_entr.outputs[src_entr.real_output].second.dest) );
        LOG_ERROR("amount " << src_entr.amount << ", rct " << src_entr.rct);
        LOG_ERROR("tx pubkey " << src_entr.real_out_tx_key << ", real_output_in_tx_index " << src_entr.real_output_in_tx_index);
        return false;
      }

      //put key image into tx input
      if (offshore_transfer || xusd_to_xasset) {  // input is xUSD

        // In-wallet swap
        txin_offshore input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;
        
        //fill outputs array and use relative offsets
        for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
          input_to_key.key_offsets.push_back(out_entry.first);
        
        input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
        tx.vin.push_back(input_to_key);
	
      } else if (onshore) {   // input is xUSD

        // Onshoring
        txin_onshore input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;
        
        //fill outputs array and use relative offsets
        for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
          input_to_key.key_offsets.push_back(out_entry.first);
        
        input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
        tx.vin.push_back(input_to_key);
        
      } else if (xasset_to_xusd || xasset_transfer) {  // input is xAsset

        // xAsset to xUSD
        txin_xasset input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;
        input_to_key.asset_type = src_entr.asset_type;
        
        //fill outputs array and use relative offsets
        for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
          input_to_key.key_offsets.push_back(out_entry.first);
        
        input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
        tx.vin.push_back(input_to_key);
	
      } else {

        // NEAC - bOffshoreTx doesn't matter if it's an OFFSHORE TX - the IN will still be txin_to_key
        txin_to_key input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = msout ? rct::rct2ki(src_entr.multisig_kLRki.ki) : img;
        
        //fill outputs array and use relative offsets
        for(const tx_source_entry::output_entry& out_entry: src_entr.outputs)
          input_to_key.key_offsets.push_back(out_entry.first);
        
        input_to_key.key_offsets = absolute_output_offsets_to_relative(input_to_key.key_offsets);
        tx.vin.push_back(input_to_key);
      }
    }

    // calculate offshore fees before shuffling destinations
    uint64_t fee = 0;
    uint64_t fee_usd = 0;
    uint64_t fee_xasset = 0;
    uint64_t offshore_fee = 0;
    uint64_t offshore_fee_usd = 0;
    uint64_t offshore_fee_xasset = 0;
    bool r =
      (offshore) ? get_offshore_fee(destinations, unlock_time-current_height-1, pr, fees_version, offshore_fee, sources, current_height) :
            (onshore) ? get_onshore_fee(destinations, unlock_time-current_height-1, pr, fees_version, offshore_fee_usd, sources, current_height) :
      (offshore_transfer) ? get_offshore_to_offshore_fee(destinations, unlock_time-current_height-1, pr, fees_version, offshore_fee_usd, sources, current_height) :
      (xusd_to_xasset) ? get_xusd_to_xasset_fee(destinations, unlock_time-current_height-1, pr, fees_version, offshore_fee_usd, sources, current_height) :
      (xasset_to_xusd) ? get_xasset_to_xusd_fee(destinations, unlock_time-current_height-1, pr, fees_version, offshore_fee_xasset, sources, current_height) :
      (xasset_transfer) ? true :
      true;
    if (!r) {
      LOG_ERROR("failed to get offshore fee - aborting");
      return false;
    }

    if (shuffle_outs)
    {
      std::shuffle(destinations.begin(), destinations.end(), crypto::random_device{});
    }

    // sort ins by their key image
    std::vector<size_t> ins_order(sources.size());
    for (size_t n = 0; n < sources.size(); ++n)
      ins_order[n] = n;
    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
      if (offshore_transfer || xusd_to_xasset) {
        const txin_offshore &tk0 = boost::get<txin_offshore>(tx.vin[i0]);
        const txin_offshore &tk1 = boost::get<txin_offshore>(tx.vin[i1]);
        return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      } else if (onshore) {
        const txin_onshore &tk0 = boost::get<txin_onshore>(tx.vin[i0]);
        const txin_onshore &tk1 = boost::get<txin_onshore>(tx.vin[i1]);
        return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      } else if (xasset_to_xusd || xasset_transfer) {
        const txin_xasset &tk0 = boost::get<txin_xasset>(tx.vin[i0]);
        const txin_xasset &tk1 = boost::get<txin_xasset>(tx.vin[i1]);
        return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      } else {
        const txin_to_key &tk0 = boost::get<txin_to_key>(tx.vin[i0]);
        const txin_to_key &tk1 = boost::get<txin_to_key>(tx.vin[i1]);
        return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
      }
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

    uint64_t summary_outs_money = 0, summary_outs_money_usd = 0, summary_outs_money_xasset = 0;


    std::vector<std::pair<std::string, uint64_t>> outamounts;
    rct::keyV destination_keys;
    uint64_t amount_out = 0;

    //fill outputs
    size_t output_index = 0;
    for(const tx_destination_entry& dst_entr: destinations)
    {
      CHECK_AND_ASSERT_MES(dst_entr.amount > 0 || tx.version > 1, false, "Destination with wrong amount: " << dst_entr.amount);
      crypto::public_key out_eph_public_key;

      tx_destination_entry dst_entr_clone = dst_entr;
      hwdev.generate_output_ephemeral_keys(
        tx.version,sender_account_keys,
        txkey_pub,
        tx_key,
        dst_entr_clone,
        change_addr,
        output_index,
        need_additional_txkeys,
        additional_tx_keys,
        additional_tx_public_keys,
        amount_keys,
        out_eph_public_key
      );

      tx_out out;
      out.amount = dst_entr_clone.amount;

      if (dst_entr_clone.asset_type == "XHV") {
        txout_to_key tk;
        tk.key = out_eph_public_key;
        out.target = tk;
        outamounts.push_back(std::pair<std::string, uint64_t>("XHV", dst_entr_clone.amount));
      } else if (dst_entr_clone.asset_type == "XUSD") {
        txout_offshore tk;
        tk.key = out_eph_public_key;
        out.target = tk;
        out.amount = dst_entr_clone.amount_usd;
         outamounts.push_back(std::pair<std::string, uint64_t>("XUSD", dst_entr_clone.amount_usd));
      } else {
        txout_xasset tk;
        tk.key = out_eph_public_key;
	tk.asset_type = dst_entr_clone.asset_type;
        out.target = tk;
        out.amount = dst_entr_clone.amount_xasset;
        outamounts.push_back(std::pair<std::string, uint64_t>(dst_entr_clone.asset_type, dst_entr_clone.amount_xasset));
      }

      // pusdh to outputs
      tx.vout.push_back(out);
      output_index++;

      // calculate total monry
      summary_outs_money += dst_entr_clone.amount;
      summary_outs_money_usd += dst_entr_clone.amount_usd;
      summary_outs_money_xasset += dst_entr_clone.amount_xasset;

      destination_keys.push_back(rct::pk2rct(out_eph_public_key));
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

    if (!sort_tx_extra(tx.extra, tx.extra)) {
      LOG_ERROR("Failed to sort_tx_extra");
      return false;
    }

    //check money
    LOG_ERROR("SIM=" << summary_inputs_money);
    LOG_ERROR("SIMu=" << summary_inputs_money_usd);
    LOG_ERROR("SIMX=" << summary_inputs_money_xasset);
    LOG_ERROR("SOM=" << summary_outs_money);
    LOG_ERROR("SOMu=" << summary_outs_money_usd);
    LOG_ERROR("SOMX=" << summary_outs_money_xasset);
    
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
          crypto::generate_ring_signature(tx_prefix_hash, boost::get<txin_to_key>(tx.vin[i]).k_image, keys_ptrs, in_contexts[i].in_ephemeral.sec, src_entr.real_output, sigs.data());
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

      uint64_t amount_in = 0;
      rct::ctkeyV inSk;
      inSk.reserve(sources.size());
      // mixRing indexing is done the other way round for simple
      rct::ctkeyM mixRing(use_simple_rct ? sources.size() : n_total_outs);
      std::vector<uint64_t> inamounts;
      std::vector<unsigned int> index;
      std::vector<rct::multisig_kLRki> kLRki;
      for (size_t i = 0; i < sources.size(); ++i)
      {
	      rct::ctkey ctkey;
        rct::ctkeyV ctkeyV; // LA
        
        inamounts.push_back(sources[i].amount);
        index.push_back(sources[i].real_output);
        // inSk: (secret key, mask)
        ctkey.dest = rct::sk2rct(in_contexts[i].in_ephemeral.sec);
        ctkey.mask = sources[i].mask;
	      ctkeyV.push_back(ctkey);
        inSk.push_back(ctkey);
        memwipe(&ctkey, sizeof(rct::ctkey));
        // inPk: (public key, commitment)
        // will be done when filling in mixRing
        if (msout)
        {
          kLRki.push_back(sources[i].multisig_kLRki);
        }
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

      if (summary_inputs_money > summary_outs_money) {
        fee = summary_inputs_money - summary_outs_money - offshore_fee;
        if (!use_simple_rct) {
          outamounts.push_back(std::pair<std::string, uint64_t>("XHV", fee));
        }
      } else if (summary_inputs_money_usd > summary_outs_money_usd) {
        fee_usd = summary_inputs_money_usd - summary_outs_money_usd - offshore_fee_usd;
        if (!use_simple_rct) {
          outamounts.push_back(std::pair<std::string, uint64_t>("XUSD", fee_usd));
        }
      } else if (summary_inputs_money_xasset > summary_outs_money_xasset) {
	      fee_xasset = summary_inputs_money_xasset - summary_outs_money_xasset - offshore_fee_xasset;
        if (!use_simple_rct) {
          outamounts.push_back(std::pair<std::string, uint64_t>(strSource, fee_xasset));
        }
      }

      // zero out all amounts to mask rct outputs, real amounts are now encrypted
      for (size_t i = 0; i < tx.vin.size(); ++i)
      {
        if (sources[i].rct) {
          if (tx.vin[i].type() == typeid(txin_offshore)) {
	          boost::get<txin_offshore>(tx.vin[i]).amount = 0;
	        }
          else if (tx.vin[i].type() == typeid(txin_onshore)) {
            boost::get<txin_onshore>(tx.vin[i]).amount = 0;
          }
          else if (tx.vin[i].type() == typeid(txin_xasset)) {
            boost::get<txin_xasset>(tx.vin[i]).amount = 0;
          }
          else {
            boost::get<txin_to_key>(tx.vin[i]).amount = 0;
          }
        }
      }

      // zero out destination amounts
      for (size_t i = 0; i < tx.vout.size(); ++i) {
        // fill the amount minted before amounts go encrypted if it is a conversion
        if (bOffshoreTx) {
          if (offshore && tx.vout[i].target.type() == typeid(txout_offshore))
            tx.amount_minted += tx.vout[i].amount;
          else if (onshore && tx.vout[i].target.type() == typeid(txout_to_key))
            tx.amount_minted += tx.vout[i].amount;
          else if (xusd_to_xasset && tx.vout[i].target.type() == typeid(txout_xasset))
            tx.amount_minted += tx.vout[i].amount;
          else if (xasset_to_xusd && tx.vout[i].target.type() == typeid(txout_offshore))
            tx.amount_minted += tx.vout[i].amount;
        }
        tx.vout[i].amount = 0;
      }

      // Calculate amount_burnt from the amount_minted
      if (bOffshoreTx) {
        if (offshore) {
          double d_xusd_amount = boost::lexical_cast<double>(tx.amount_minted);
          double d_exchange_rate = boost::lexical_cast<double>(pr.unused1);
          tx.amount_burnt = (uint64_t)((d_xusd_amount / d_exchange_rate) * 1000000000000.0);
        } else if (onshore) {
          double d_xhv_amount = boost::lexical_cast<double>(tx.amount_minted) / 1000000000000.0;
          double d_exchange_rate = boost::lexical_cast<double>(pr.unused1);
          tx.amount_burnt = (uint64_t)(d_xhv_amount * d_exchange_rate);
        } else if (offshore_transfer) {
          tx.amount_burnt = tx.amount_minted = 0;
        } else if (xusd_to_xasset) {
          double d_xasset_amount = boost::lexical_cast<double>(tx.amount_minted);
          double d_exchange_rate = boost::lexical_cast<double>(pr[strDest]);
          tx.amount_burnt = (uint64_t)((d_xasset_amount / d_exchange_rate) * 1000000000000.0);
        } else if (xasset_to_xusd) {
          double d_xusd_amount = boost::lexical_cast<double>(tx.amount_minted) / 1000000000000.0;
          double d_exchange_rate = boost::lexical_cast<double>(pr[strSource]);
          tx.amount_burnt = (uint64_t)(d_xusd_amount * d_exchange_rate);
        } else if (xasset_transfer) {
          tx.amount_burnt = tx.amount_minted = 0;
        }
        if ((offshore || onshore || xasset_to_xusd || xusd_to_xasset) && (!tx.amount_burnt || !tx.amount_minted)) {
          LOG_ERROR("Invalid offshore TX - amount too small (<1 ATOMIC_UNIT)");
          return false;
        }
      }
      
      crypto::hash tx_prefix_hash;
      get_transaction_prefix_hash(tx, tx_prefix_hash, hwdev);
      rct::ctkeyV outSk;
      if (use_simple_rct)
        tx.rct_signatures = rct::genRctSimple(rct::hash2rct(tx_prefix_hash), inSk, destination_keys, inamounts, strSource, outamounts, fee, fee_usd, fee_xasset, offshore_fee, offshore_fee_usd, offshore_fee_xasset, mixRing, amount_keys, msout ? &kLRki : NULL, msout, index, outSk, rct_config, hwdev, pr);
      else
        tx.rct_signatures = rct::genRct(rct::hash2rct(tx_prefix_hash), inSk, strSource, destination_keys, outamounts, mixRing, amount_keys, msout ? &kLRki[0] : NULL, msout, sources[0].real_output, outSk, rct_config, hwdev); // same index assumption
      for (size_t i=0; i<inSk.size(); i++) {
      	memwipe(&inSk[i], sizeof(rct::ctkeyV));
      }

      CHECK_AND_ASSERT_MES(tx.vout.size() == outSk.size(), false, "outSk size does not match vout");

      MCINFO("construct_tx", "transaction_created: " << get_transaction_hash(tx) << ENDL << obj_to_json_str(tx) << ENDL);
    }

    tx.invalidate_hashes();

    return true;
  }
  //---------------------------------------------------------------
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, uint64_t current_height, offshore::pricing_record pr, uint32_t fees_version, bool use_offshore_tx_version, bool rct, const rct::RCTConfig &rct_config, rct::multisig_out *msout)
  {
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
        for (const auto &d: destinations)
          additional_tx_keys.push_back(keypair::generate(sender_account_keys.get_device()).sec);
      }

      bool r = construct_tx_with_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, current_height, pr, fees_version, use_offshore_tx_version, rct, rct_config, msout);
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
     offshore::pricing_record pr;
     std::vector<crypto::secret_key> additional_tx_keys;
     std::vector<tx_destination_entry> destinations_copy = destinations;
     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations_copy, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys, 0, pr, 1, false, false, { rct::RangeProofBorromean, 0}, NULL);
  }
  //---------------------------------------------------------------
  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    , cryptonote::network_type nettype
    )
  {
    //genesis block
    bl = {};
    account_public_address ac = boost::value_initialized<account_public_address>();
    std::vector<size_t> sz;
    std::map<std::string, uint64_t> fee_map, offshore_fee_map;
    construct_miner_tx(0, 0, 0, 0, fee_map, offshore_fee_map, ac, bl.miner_tx, blobdata(), 999, 1, nettype); // zero fee in genesis
    blobdata txb = tx_to_blob(bl.miner_tx);
    std::string hex_tx_represent = string_tools::buff_to_hex_nodelimer(txb);

    std::string genesis_coinbase_tx_hex = config::GENESIS_TX;

    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(genesis_coinbase_tx_hex, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = nonce;
    miner::find_nonce_for_given_block([](const cryptonote::block &b, uint64_t height, unsigned int threads, crypto::hash &hash){
      return cryptonote::get_block_longhash(NULL, b, hash, height, threads);
    }, bl, 1, 0);
    bl.invalidate_hashes();
    return true;
  }
  //---------------------------------------------------------------
  void get_altblock_longhash(const block& b, crypto::hash& res, const uint64_t main_height, const uint64_t height, const uint64_t seed_height, const crypto::hash& seed_hash)
  {
    blobdata bd = get_block_hashing_blob(b);
    rx_slow_hash(main_height, seed_height, seed_hash.data, bd.data(), bd.size(), res.data, 0, 1);
  }

  bool get_block_longhash(const Blockchain *pbc, const block& b, crypto::hash& res, const uint64_t height, const int miners)
  {
    block b_local = b; //workaround to avoid const errors with do_serialize
    blobdata bd = get_block_hashing_blob(b);
    cn_pow_hash_v3 ctx;
    if(b_local.major_version >= CRYPTONOTE_V3_POW_BLOCK_VERSION)
    {
      ctx.hash(bd.data(), bd.size(), res.data);
    }
    else if(b_local.major_version == CRYPTONOTE_V2_POW_BLOCK_VERSION)
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
  }

  crypto::hash get_block_longhash(const Blockchain *pbc, const block& b, const uint64_t height, const int miners)
  {
    crypto::hash p = crypto::null_hash;
    get_block_longhash(pbc, b, p, height, miners);
    return p;
  }

  void get_block_longhash_reorg(const uint64_t split_height)
  {
    rx_reorg(split_height);
  }
}
