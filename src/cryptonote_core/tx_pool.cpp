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

#include <algorithm>
#include <boost/filesystem.hpp>
#include <unordered_set>
#include <vector>

#include "tx_pool.h"
#include "cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_config.h"
#include "blockchain.h"
#include "blockchain_db/locked_txn.h"
#include "blockchain_db/blockchain_db.h"
#include "common/boost_serialization_helper.h"
#include "int-util.h"
#include "misc_language.h"
#include "warnings.h"
#include "common/perf_timer.h"
#include "crypto/hash.h"
#include "crypto/duration.h"
#include "offshore/asset_types.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "txpool"

DISABLE_VS_WARNINGS(4244 4345 4503) //'boost::foreach_detail_::or_' : decorated name length exceeded, name was truncated

using namespace crypto;

namespace cryptonote
{
  namespace
  {
    /*! The Dandelion++ has formula for calculating the average embargo timeout:
                          (-k*(k-1)*hop)/(2*log(1-ep))
        where k is the number of hops before this node and ep is the probability
        that one of the k hops hits their embargo timer, and hop is the average
        time taken between hops. So decreasing ep will make it more probable
        that "this" node is the first to expire the embargo timer. Increasing k
        will increase the number of nodes that will be "hidden" as a prior
        recipient of the tx.

        As example, k=5 and ep=0.1 means "this" embargo timer has a 90%
        probability of being the first to expire amongst 5 nodes that saw the
        tx before "this" one. These values are independent to the fluff
        probability, but setting a low k with a low p (fluff probability) is
        not ideal since a blackhole is more likely to reveal earlier nodes in
        the chain.

        This value was calculated with k=5, ep=0.10, and hop = 175 ms. A
        testrun from a recent Intel laptop took ~80ms to
        receive+parse+proces+send transaction. At least 50ms will be added to
        the latency if crossing an ocean. So 175ms is the fudge factor for
        a single hop with 39s being the embargo timer. */
    constexpr const std::chrono::seconds dandelionpp_embargo_average{CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE};

    //TODO: constants such as these should at least be in the header,
    //      but probably somewhere more accessible to the rest of the
    //      codebase.  As it stands, it is at best nontrivial to test
    //      whether or not changing these parameters (or adding new)
    //      will work correctly.
    time_t const MIN_RELAY_TIME = (60 * 5); // only start re-relaying transactions after that many seconds
    time_t const MAX_RELAY_TIME = (60 * 60 * 4); // at most that many seconds between resends
    float const ACCEPT_THRESHOLD = 1.0f;

    //! Max DB check interval for relayable txes
    constexpr const std::chrono::minutes max_relayable_check{2};

    constexpr const std::chrono::seconds forward_delay_average{CRYPTONOTE_FORWARD_DELAY_AVERAGE};

    // a kind of increasing backoff within min/max bounds
    uint64_t get_relay_delay(time_t last_relay, time_t received)
    {
      time_t d = (last_relay - received + MIN_RELAY_TIME) / MIN_RELAY_TIME * MIN_RELAY_TIME;
      if (d > MAX_RELAY_TIME)
        d = MAX_RELAY_TIME;
      return d;
    }

    uint64_t template_accept_threshold(uint64_t amount)
    {
      return amount * ACCEPT_THRESHOLD;
    }

    uint64_t get_transaction_weight_limit(uint8_t version)
    {
      // from v8, limit a tx to 50% of the minimum block weight
      if (version >= 5)
        return get_min_block_weight(version) / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
      else
        return get_min_block_weight(version) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    }

    // external lock must be held for the comparison+set to work properly
    void set_if_less(std::atomic<time_t>& next_check, const time_t candidate) noexcept
    {
      if (candidate < next_check.load(std::memory_order_relaxed))
        next_check = candidate;
    }
  }
  //---------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------
  tx_memory_pool::tx_memory_pool(Blockchain& bchs): m_blockchain(bchs), m_cookie(0), m_txpool_max_weight(DEFAULT_TXPOOL_MAX_WEIGHT), m_txpool_weight(0), m_mine_stem_txes(false), m_next_check(std::time(nullptr))
  {
    // class code expects unsigned values throughout
    if (m_next_check < time_t(0))
      throw std::runtime_error{"Unexpected time_t (system clock) value"};
  }
  //---------------------------------------------------------------------------------
  uint64_t tx_memory_pool::get_tx_unlock_time(uint64_t tx_unlock_time, uint64_t tx_pr_height, uint64_t current_height)
  {
    uint64_t unlock_time = 0;
    if (current_height > 973672) {
      if (tx_unlock_time > tx_pr_height) {
        unlock_time = tx_unlock_time - tx_pr_height;
      }
    } else {
      unlock_time = tx_unlock_time - tx_pr_height;
    }
    return unlock_time;
  }
  //---------------------------------------------------------------------------------
  uint64_t tx_memory_pool::get_xhv_fee_amount(const std::string& fee_asset, uint64_t fee_amount, const cryptonote::transaction_type tt, const offshore::pricing_record& pr, const uint16_t hf_version)
  {
    // Handle case where currency has been disabled in PR
    //if (fee_asset != "XHV" && (!pr.unused1 || !pr.xUSD || !pr[fee_asset])) {
    if (fee_asset != "XHV" && (!pr.ma("XHV") || !pr.spot("XHV") || !pr.spot(fee_asset))) {
      return fee_amount;
    } 

    uint64_t total_fee_xhv = 0;
    if (fee_asset == "XHV") {
      total_fee_xhv = fee_amount;
    } else if (fee_asset == "XUSD") {
      // convert the fee into xhv
      total_fee_xhv = cryptonote::get_xhv_amount(fee_amount, pr, tt, hf_version);
    } else {
      // convert xasset to xusd
      uint64_t xusd_amount = cryptonote::get_xusd_amount(fee_amount, fee_asset, pr, tt, hf_version);
      // convert to xhv
      total_fee_xhv = cryptonote::get_xhv_amount(xusd_amount, pr, tt, hf_version);
    }
    return total_fee_xhv;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx2(transaction &tx, const crypto::hash &id, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t hf_version)
  {
    using tt = cryptonote::transaction_type;
    const bool kept_by_block = (tx_relay == relay_method::block);

    // this should already be called with that lock, but let's make it explicit for clarity
    CRITICAL_REGION_LOCAL(m_transactions_lock);

    PERF_TIMER(add_tx);

    // we do not accept transactions that timed out before, unless they're
    // kept_by_block
    if (!kept_by_block && m_timed_out_transactions.find(id) != m_timed_out_transactions.end())
    {
      // not clear if we should set that, since verifivation (sic) did not fail before, since
      // the tx was accepted before timing out.
      tvc.m_verifivation_failed = true;
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    // Block the use of timestamps for unlock_time
    if(tx.unlock_time >= CRYPTONOTE_MAX_BLOCK_NUMBER) {
      tvc.m_verifivation_failed = true;
      return false;
    }

    // From HF18, only allow TX version 5+
    if (tx.version < 5) {
      LOG_ERROR("Only 5+ transaction version are permitted after HAVEN2 hard fork(version 18)");
      tvc.m_verifivation_failed = true;
      return false;
    } else if (hf_version == HF_PER_OUTPUT_UNLOCK_VERSION && tx.version != POU_TRANSACTION_VERSION) {
      LOG_ERROR("Only v6 transaction version are permitted after PER_OUTPUT_LOCK hard fork(version 19)");
      tvc.m_verifivation_failed = true;
      return false;
    } else if (hf_version == HF_VERSION_USE_COLLATERAL && tx.version != COLLATERAL_TRANSACTION_VERSION) {
      LOG_ERROR("Only v7 transaction version are permitted after Haven3 hard fork(v20)");
      tvc.m_verifivation_failed = true;
      return false;
    }

    // fees
    uint64_t fee = tx.rct_signatures.txnFee;
    uint64_t offshore_fee = tx.rct_signatures.txnOffshoreFee;
    
    // Check to make sure that only 1 destination is provided if memo data is specified.
    // This is necessary because we shuffle outputs and there is no way to identify which memo data would relate to which destination if multiples were permitted.
    tx_extra_memo memo;
    if (get_memo_from_tx_extra(tx.extra, memo)) {
      if (tx.vout.size() > 2) {
        LOG_PRINT_L1("transaction has memo data and multiple destinations specified - this is not permitted, rejecting.");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }

    // get vars we need from tvc
    std::string source = tvc.m_source_asset;
    std::string dest = tvc.m_dest_asset;
    tt tx_type = tvc.m_type;
    // since tvc can be empty for some situations such as "popping blocks",
    // we make sure those vars are populated.
    if (source.empty() || dest.empty() || tx_type == transaction_type::UNSET) {
      if (!get_tx_asset_types(tx, id, source, dest, false)) {
        LOG_PRINT_L1("At least 1 input or 1 output of the tx was invalid." << id);
        tvc.m_verifivation_failed = true;
        if (source.empty()) {
          tvc.m_invalid_input = true;
        }
        if (dest.empty()) {
          tvc.m_invalid_output = true;
        }
        return false;
      }
      if (!get_tx_type(source, dest, tx_type)) {
        LOG_ERROR("At least 1 input or 1 output of the tx was invalid." << id);
        tvc.m_verifivation_failed = true;
        return false;
      }
      // now populate the tvc
      tvc.m_source_asset = source;
      tvc.m_dest_asset = dest;
      tvc.m_type = tx_type;
    }

    // check whether this is a conversion tx.
    if (source != dest) {

      // get pr for this tx
      uint64_t current_height = m_blockchain.get_current_blockchain_height();
      if (!tvc.tx_pr_height_verified) { // tx_pr_height_verified will only be false if poping blocks, otherwise the tx should already have been rejected.
        if (!tx_pr_height_valid(current_height, tx.pricing_record_height, id)) {
          LOG_ERROR("Tx uses older pricing record than what is allowed. Current height: " << current_height << " Pr height: " << tx.pricing_record_height);
          tvc.m_verifivation_failed = true;
          return false;
        } else {
          tvc.tx_pr_height_verified = true;
        }
      }
      if(tvc.pr.empty()) {
        // Get the pricing record that was used for conversion
        block bl;
        bool r = m_blockchain.get_block_by_hash(m_blockchain.get_block_id_by_height(tx.pricing_record_height), bl);
        if (!r) {
          LOG_ERROR("error: failed to get block containing pricing record");
          tvc.m_verifivation_failed = true;
          return false;
        }
        tvc.pr = bl.pricing_record;
      }

      // check whether we have a valid exchange rate (some values in the pr might be 0)
      if (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE) {
        if (!tvc.pr.ma("XHV")) { // using 24 hr MA in unused1
          LOG_ERROR("error: empty MA exchange rate. Conversion not possible.");
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION && !tvc.pr.spot("XHV")) { // could be using spot for xUSD
          LOG_ERROR("error: empty spot exchange rate. Conversion not possible.");
          tvc.m_verifivation_failed = true;
          return false;
        }
      } else if (tx_type == tt::XUSD_TO_XASSET) {
        if (!tvc.pr.spot(dest)) {
          LOG_ERROR("error: empty exchange rate. Conversion not possible.");
          tvc.m_verifivation_failed = true;
          return false;
        }
      } else if (tx_type == tt::XASSET_TO_XUSD) {
        if (!tvc.pr.spot(source)) {
          LOG_ERROR("error: empty exchange rate. Conversion not possible.");
          tvc.m_verifivation_failed = true;
          return false;
        }
      } else {
        LOG_ERROR("error: wrong tx type set.");
        tvc.m_verifivation_failed = true;
        return false;
      }

      // List of dead asset types
      std::vector<std::string> dead_asset_types = {"XAUD", "XCHF", "XCNY", "XGBP", "XEUR"};

      // Reject the dead asset types as destinations
      if (hf_version >= HF_VERSION_SLIPPAGE && tx_type == tt::XUSD_TO_XASSET && std::count(dead_asset_types.begin(), dead_asset_types.end(), dest)) {
        LOG_ERROR("error: Invalid Tx found. Asset type '" << dest << "' cannot be minted after HF " << HF_VERSION_SLIPPAGE << " - rejecting TX");
        tvc.m_verifivation_failed = true;
        return false;
      }
      
      // Get the circulating supply amounts
      const std::vector<std::pair<std::string, std::string>>& supply_amounts = m_blockchain.get_db().get_circulating_supply();

      // Get the slippage
      uint64_t slippage = 0;
      if (hf_version >= HF_VERSION_SLIPPAGE && source != dest) {
        if (!get_slippage(tx_type, source, dest, tx.amount_burnt, slippage, tvc.pr, supply_amounts, hf_version)) {
          LOG_ERROR("error: Invalid Tx found. 0 burnt/minted for a conversion tx.");
          tvc.m_verifivation_failed = true;
          return false;
        }
      }

      // check whether we have empty amount burnt/mint. Actual validation happens in verRctSemanticsSimple2()
      if (!tx.amount_burnt || !tx.amount_minted) {
        LOG_ERROR("error: Invalid Tx found. 0 burnt/minted for a conversion tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }

      // Get the conversion rate used
      uint64_t conversion_rate = COIN;
      if (!cryptonote::get_conversion_rate(tvc.pr, source, dest, conversion_rate, hf_version)) {
        LOG_ERROR("error: unable to obtain conversion rate.");
        tvc.m_verifivation_failed = true;
        return false;
      }
      
      // Get the fee conversion rate used
      uint64_t fee_conversion_rate = COIN;
      if (!cryptonote::get_conversion_rate(tvc.pr, source, "XHV", fee_conversion_rate, hf_version)) {
        LOG_ERROR("error: unable to obtain fee conversion rate.");
        tvc.m_verifivation_failed = true;
        return false;
      }
      
      // Check the amount burnt and minted
      if (!rct::checkBurntAndMinted(tx.rct_signatures, tx.amount_burnt - slippage, tx.amount_minted, tvc.pr, conversion_rate, source, dest, hf_version)) {
        LOG_PRINT_L1("amount burnt / minted is incorrect: burnt = " << tx.amount_burnt << ", minted = " << tx.amount_minted);
        tvc.m_verifivation_failed = true;
        return false;
      }

      // Iterate over the outputs, allowing change to have a shorter unlock time (we need the index!)
      bool found_collateral_output = false;
      bool found_collateral_change_output = false;
      for (size_t i = 0; i < tx.vout.size(); ++i) {

        // Check if the output is collateral or collateral_change
        bool is_collateral = false;
        bool is_collateral_change = false;
        bool ok = cryptonote::is_output_collateral(tx.vout[i], is_collateral, is_collateral_change);
        if (!ok) {
          LOG_ERROR("failed to get output collateral status for output index " << i);
          tvc.m_verifivation_failed = true;
          return false;
        }
        if (hf_version >= HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS) {
          if (is_collateral) {
            if (found_collateral_output) {
              LOG_ERROR("Too many collateral outputs present in TX at output index " << i);
              tvc.m_verifivation_failed = true;
              return false;
            }
            found_collateral_output = true;
          }
          if (is_collateral_change) {
            if (found_collateral_change_output) {
              LOG_ERROR("Too many collateral change outputs present in TX at output index " << i);
              tvc.m_verifivation_failed = true;
              return false;
            }
            found_collateral_change_output = true;
          }
        }
        
        // Check if the output asset type is the same as the source
        std::string output_asset_type;
        ok = cryptonote::get_output_asset_type(tx.vout[i], output_asset_type);
        if (!ok) {
          LOG_ERROR("failed to get output asset type for output index " << i);
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Check output unlock time
        uint64_t output_unlock_time;
        ok = cryptonote::get_output_unlock_time(tx.vout[i], output_unlock_time);
        if (!ok) {
          LOG_ERROR("failed to get output unlock time for output index " << i);
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Skip output unlock time check if it's change for a conversion
        if (source != output_asset_type || is_collateral || is_collateral_change) {

          // Check the unlock time (use the PR height in case of TX being left in pool for >1 block - PR height validated as acceptable elsewhere)
          ok = m_blockchain.check_unlock_time(output_unlock_time, tx.pricing_record_height, tx_type, output_asset_type, is_collateral, is_collateral_change, hf_version);
          if (!ok) {
            LOG_ERROR("incorrect output unlock time for output index " << i);
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      }
      
      // validate conversion fees
      uint64_t conversion_fee_check = 0;
      if (hf_version >= HF_VERSION_CONVERSION_FEES_IN_XHV) {
        
        // Flat 1.5% fee IN XHV!!!
        if (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE || tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD) {

          // Calculate 1.5% of amount_burnt
          boost::multiprecision::uint128_t conversion_fee_amount_128 = tx.amount_burnt;
          conversion_fee_amount_128 *= 3;
          conversion_fee_amount_128 /= 200;

          // Convert to XHV for fee comparison
          conversion_fee_amount_128 *= fee_conversion_rate;
          conversion_fee_amount_128 /= COIN;
          conversion_fee_check = (uint64_t)conversion_fee_amount_128;
        } else {
          // Should never happen
          LOG_ERROR("incorrect TX type for conversion");
          tvc.m_verifivation_failed = true;
          return false;
        }
          
      } else if (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE) {
        if (hf_version >= HF_VERSION_USE_COLLATERAL) {
          // Flat 1.5% fee
          boost::multiprecision::uint128_t amount_128 = tx.amount_burnt;
          amount_128 *= 3;
          amount_128 /= 200;
          conversion_fee_check = (uint64_t)amount_128;
        } else if (hf_version >= HF_PER_OUTPUT_UNLOCK_VERSION) {
          // Flat 0.5% fee
          conversion_fee_check = tx.amount_burnt / 200;
        } else {
          uint64_t unlock_time = tx.unlock_time - tx.pricing_record_height - 1;
          uint64_t priority = (unlock_time >= 5040) ? 1 : (unlock_time >= 1440) ? 2 : (unlock_time >= 720) ? 3 : 4;
          conversion_fee_check = (priority == 1) ? tx.amount_burnt / 500 : (priority == 2) ? tx.amount_burnt / 20 : (priority == 3) ? tx.amount_burnt / 10 : tx.amount_burnt / 5;
        }
      } else if (tx_type == tt::XASSET_TO_XUSD || tx_type == tt::XUSD_TO_XASSET) {
        if (hf_version >= HF_VERSION_USE_COLLATERAL) {
          // Flat 1.5% conversion fee for xAsset TXs after the collateral fork
          boost::multiprecision::uint128_t amount_128 = tx.amount_burnt;
          amount_128 *= 3;
          amount_128 /= 200;
          conversion_fee_check = (uint64_t)amount_128;
        } else {
          // Flat 0.5% conversion fee for xAsset TXs after that fork, plus an adjustment 
          // for the tx.amount_burnt containing the 80% burnt fee proportion as well
          boost::multiprecision::uint128_t amount_128 = tx.amount_burnt;
          amount_128 = (amount_128 * 10) / (2000 + 8);
          conversion_fee_check = (uint64_t)amount_128;
        }
      }

      if (conversion_fee_check != tx.rct_signatures.txnOffshoreFee) {
        LOG_PRINT_L1("conversion fee is incorrect - rejecting");
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
      }
    } else {
      // make sure there is no burnt/mint set for transfers, unless it is a burn, since these numbers will affect circulating supply.

      if ((tx.amount_burnt && hf_version<HF_VERSION_BURN)|| tx.amount_minted) {
        LOG_ERROR("error: Invalid Tx found. Amount burnt/mint > 0 for a transfer tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }
      if ((hf_version >= HF_VERSION_BURN) && tx.amount_minted) {
        LOG_ERROR("error: Invalid Tx found. Amount mint > 0 for a transfer tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }


      // make sure no pr height set
      if (tx.pricing_record_height) {
        LOG_ERROR("error: Invalid Tx found. Tx pricing_record_height > 0 for a transfer tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }
      uint64_t current_height = m_blockchain.get_current_blockchain_height();
      const bool is_audit_tx = (tx.rct_signatures.type==rct::RCTTypeSupplyAudit);
      if(is_audit_tx){
        for (size_t i = 0; i < tx.vout.size(); ++i) { //Make sure all audit tx outputs are locked for 2 days
          // Check output unlock time
          uint64_t output_unlock_time;
          bool ok = cryptonote::get_output_unlock_time(tx.vout[i], output_unlock_time);
          if (!ok) {
            LOG_ERROR("failed to get output unlock time for output index " << i);
            tvc.m_verifivation_failed = true;
            return false;
          }
          if(current_height + HF25_AUDIT_LOCK_BLOCKS  > output_unlock_time + HF25_AUDIT_LOCK_GRACE_PERIOD_BLOCKS){
            LOG_ERROR("incorrect output unlock time for output index, part of an audit tx " << i); 
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      }
    }

    // check the std tx fee
    if (!kept_by_block) {
      if (!fee || !m_blockchain.check_fee(tx_weight, fee, tvc.pr, source, dest, tx_type)){
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        tvc.m_no_drop_offense = true;
        return false;
      }
    }
    
    size_t tx_weight_limit = get_transaction_weight_limit(hf_version);
    if ((!kept_by_block || hf_version >= HF_VERSION_PER_BYTE_FEE) && tx_weight > tx_weight_limit)
    {
      LOG_PRINT_L1("transaction is too heavy: " << tx_weight << " bytes, maximum weight: " << tx_weight_limit);
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    size_t tx_extra_size = tx.extra.size();
    if (!kept_by_block && tx_extra_size > MAX_TX_EXTRA_SIZE)
    {
      LOG_PRINT_L1("transaction tx-extra is too big: " << tx_extra_size << " bytes, the limit is: " << MAX_TX_EXTRA_SIZE);
      tvc.m_verifivation_failed = true;
      tvc.m_tx_extra_too_big = true;
      tvc.m_no_drop_offense = true;
      return false;
    }

    // if the transaction came from a block popped from the chain,
    // don't check if we have its key images as spent.
    // TODO: Investigate why not?
    if(!kept_by_block)
    {
      if(have_tx_keyimges_as_spent(tx, id))
      {
        mark_double_spend(tx);
        LOG_PRINT_L1("Transaction with id= "<< id << " used already spent key images");
        tvc.m_verifivation_failed = true;
        tvc.m_double_spend = true;
        return false;
      }
    }

    if (!m_blockchain.check_tx_outputs(tx, tvc))
    {
      LOG_PRINT_L1("Transaction with id= "<< id << " has at least one invalid output");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }

    // assume failure during verification steps until success is certain
    tvc.m_verifivation_failed = true;

    time_t receive_time = time(nullptr);

    crypto::hash max_used_block_id = null_hash;
    uint64_t max_used_block_height = 0;
    cryptonote::txpool_tx_meta_t meta{};
    if ((hf_version >= HF_VERSION_CONVERSION_FEES_IN_XHV) && (source != dest)) {
      // All fees are in XHV
      strcpy(meta.fee_asset_type, "XHV");
    } else {
      // Fees are in source asset type
      strcpy(meta.fee_asset_type, source.c_str());
    }
    bool ch_inp_res = check_tx_inputs([&tx]()->cryptonote::transaction&{ return tx; }, id, max_used_block_height, max_used_block_id, tvc, kept_by_block);
    if(!ch_inp_res)
    {
      // if the transaction was valid before (kept_by_block), then it
      // may become valid again, so ignore the failed inputs check.
      if(kept_by_block)
      {
        meta.weight = tx_weight;
        meta.fee = fee;
        meta.offshore_fee = offshore_fee;
        meta.max_used_block_id = null_hash;
        meta.max_used_block_height = 0;
        meta.last_failed_height = 0;
        meta.last_failed_id = null_hash;
        meta.receive_time = receive_time;
        meta.last_relayed_time = time(NULL);
        meta.relayed = relayed;
        meta.set_relay_method(tx_relay);
        meta.double_spend_seen = have_tx_keyimges_as_spent(tx, id);
        meta.pruned = tx.pruned;
        meta.bf_padding = 0;
        memset(meta.padding1, 0, sizeof(meta.padding1));
        memset(meta.padding, 0, sizeof(meta.padding));
        try
        {
          if (kept_by_block)
            m_parsed_tx_cache.insert(std::make_pair(id, tx));
          CRITICAL_REGION_LOCAL1(m_blockchain);
          LockedTXN lock(m_blockchain.get_db());
          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.add_txpool_tx(id, blob, meta);
          // get the total fee paid in xhv if possible.
          // use directly itself otherwise.
          uint64_t total_fee = 0;
          if (tvc.pr.empty()) {
            if (!m_blockchain.get_latest_acceptable_pr(tvc.pr)) {
              total_fee = meta.fee + meta.offshore_fee;
            }
          }
          total_fee = total_fee ? total_fee : get_xhv_fee_amount(meta.fee_asset_type, meta.fee + meta.offshore_fee,  tvc.m_type, tvc.pr, hf_version);
          m_txs_by_fee_and_receive_time.emplace(std::pair<double, std::time_t>(total_fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
          lock.commit();
        }
        catch (const std::exception &e)
        {
          MERROR("Error adding transaction to txpool: " << e.what());
          return false;
        }
        tvc.m_verifivation_impossible = true;
        tvc.m_added_to_pool = true;
      }else
      {
        LOG_PRINT_L1("tx used wrong inputs, rejected");
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
      }
    } else {

      try
      {
        if (kept_by_block)
          m_parsed_tx_cache.insert(std::make_pair(id, tx));
        CRITICAL_REGION_LOCAL1(m_blockchain);
        LockedTXN lock(m_blockchain.get_db());

        const bool existing_tx = m_blockchain.get_txpool_tx_meta(id, meta);
        if (existing_tx)
        {
          /* If Dandelion++ loop. Do not use txes in the `local` state in the
             loop detection - txes in that state should be outgoing over i2p/tor
             then routed back via public dandelion++ stem. Pretend to be
             another stem node in that situation, a loop over the public
             network hasn't been hit yet. */
          if (tx_relay == relay_method::stem && meta.dandelionpp_stem)
            tx_relay = relay_method::fluff;
        }
        else
          meta.set_relay_method(relay_method::none);

        if (meta.upgrade_relay_method(tx_relay) || !existing_tx) // synchronize with embargo timer or stem/fluff out-of-order messages
        {
          //update transactions container
          meta.last_relayed_time = std::numeric_limits<decltype(meta.last_relayed_time)>::max();
          meta.receive_time = receive_time;
          meta.weight = tx_weight;
          meta.fee = fee;
          meta.offshore_fee = offshore_fee;
          meta.max_used_block_id = max_used_block_id;
          meta.max_used_block_height = max_used_block_height;
          meta.last_failed_height = 0;
          meta.last_failed_id = null_hash;
          meta.relayed = relayed;
          meta.double_spend_seen = false;
          meta.pruned = tx.pruned;
          meta.bf_padding = 0;
	        memset(meta.padding1, 0, sizeof(meta.padding1));
          memset(meta.padding, 0, sizeof(meta.padding));

          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.remove_txpool_tx(id);
          m_blockchain.add_txpool_tx(id, blob, meta);

          // get the total fee paid in xhv if possible.
          // use directly itself otherwise.
          uint64_t total_fee = 0;
          if (tvc.pr.empty()) {
            if (!m_blockchain.get_latest_acceptable_pr(tvc.pr)) {
              total_fee = meta.fee + meta.offshore_fee;
            }
          }
          total_fee = total_fee ? total_fee : get_xhv_fee_amount(meta.fee_asset_type, meta.fee + meta.offshore_fee,  tvc.m_type, tvc.pr, hf_version);
          m_txs_by_fee_and_receive_time.emplace(std::pair<double, std::time_t>(total_fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
        }
        lock.commit();
      }
      catch (const std::exception &e)
      {
        MERROR("internal error: error adding transaction to txpool: " << e.what());
        return false;
      }
      tvc.m_added_to_pool = true;

      static_assert(unsigned(relay_method::none) == 0, "expected relay_method::none value to be zero");
      if(meta.fee > 0){
        tvc.m_relay = tx_relay;
      }
    }

    tvc.m_verifivation_failed = false;
    m_txpool_weight += tx_weight;

    ++m_cookie;

    MINFO("Transaction added to pool: txid " << id << " weight: " << tx_weight << " fee/byte: " << (meta.fee / (double)(tx_weight ? tx_weight : 1)) << " " << source);

    prune(m_txpool_max_weight);

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, /*const crypto::hash& tx_prefix_hash,*/ const crypto::hash &id, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t hf_version)
  {
    const bool kept_by_block = (tx_relay == relay_method::block);

    // this should already be called with that lock, but let's make it explicit for clarity
    CRITICAL_REGION_LOCAL(m_transactions_lock);

    PERF_TIMER(add_tx);
    if (tx.version == 0)
    {
      // v0 never accepted
      LOG_PRINT_L1("transaction version 0 is invalid");
      tvc.m_verifivation_failed = true;
      return false;
    }

    // we do not accept transactions that timed out before, unless they're
    // kept_by_block
    if (!kept_by_block && m_timed_out_transactions.find(id) != m_timed_out_transactions.end())
    {
      // not clear if we should set that, since verifivation (sic) did not fail before, since
      // the tx was accepted before timing out.
      tvc.m_verifivation_failed = true;
      return false;
    }

    if(!check_inputs_types_supported(tx))
    {
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_input = true;
      return false;
    }

    // Block the use of timestamps for unlock_time
    if(hf_version >= HF_VERSION_XASSET_FEES_V2 && tx.unlock_time >= CRYPTONOTE_MAX_BLOCK_NUMBER) {
      tvc.m_verifivation_failed = true;
      return false;
    }

    // From HF17, only allow TX version 4+
    if(hf_version >= HF_VERSION_XASSET_FEES_V2 && tx.version < 4) {
      tvc.m_verifivation_failed = true;
      return false;
    }

    // fee per kilobyte, size rounded up.
    uint64_t fee = tx.rct_signatures.txnFee;
    uint64_t offshore_fee = tx.rct_signatures.txnOffshoreFee;
    uint64_t fee_usd = tx.rct_signatures.txnFee_usd;
    uint64_t fee_xasset = tx.rct_signatures.txnFee_xasset;
    uint64_t offshore_fee_usd = tx.rct_signatures.txnOffshoreFee_usd;
    uint64_t offshore_fee_xasset = tx.rct_signatures.txnOffshoreFee_xasset;

    //validate the offshore data
    bool bOffshoreTx = false;
    tx_extra_offshore offshore_data;
    if (tx.extra.size()) {
      bOffshoreTx = get_offshore_from_tx_extra(tx.extra, offshore_data);
    }
    if (bOffshoreTx) {
      if (hf_version >= HF_VERSION_XASSET_FULL) {
        int pos = offshore_data.data.find("-");
        if (pos != std::string::npos) {
          std::string source = offshore_data.data.substr(0,pos);
          std::string dest = offshore_data.data.substr(pos+1);
          // check both strSource and strDest are supported.
          if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), source) == offshore::ASSET_TYPES.end()) {
            tvc.m_verifivation_failed = true;
            LOG_PRINT_L1("Source Asset type " << source << " is not supported! Rejecting..");
            return false;
          }
          if (std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), dest) == offshore::ASSET_TYPES.end()) {
            tvc.m_verifivation_failed = true;
            LOG_PRINT_L1("Destination Asset type " << dest << " is not supported! Rejecting..");
            return false;
          }
        } else {
          LOG_PRINT_L1("Invalid offshore data format was supplied to tx." << id);
          tvc.m_verifivation_failed = true;
          return false;
        }
      } else if (hf_version >= HF_VERSION_OFFSHORE_FULL) {
        if (offshore_data.data.size() != 2 ||
            (offshore_data.data.at(0) != 'A' && offshore_data.data.at(0) != 'N') || 
            (offshore_data.data.at(1) != 'A' && offshore_data.data.at(1) != 'N')
            ){
          // old offshore data format suplied to tx extra
          LOG_PRINT_L1("Invalid offshore data format was supplied to tx." << id);
          tvc.m_verifivation_failed = true;
          return false;
        }
      }

      std::string tx_offshore_data(tx.offshore_data.begin(), tx.offshore_data.end());
      if(tx_offshore_data.empty()) {
        if (hf_version >= HF_VERSION_XASSET_FULL) {
          // old offshore data format suplied to tx extra
          LOG_PRINT_L1("Empty tx_offshore_data." << id);
          tvc.m_verifivation_failed = true;
          return false;
        } else if (hf_version >= HF_VERSION_OFFSHORE_FULL) {
          // offshore_data must be "NN"
          if (offshore_data.data != "NN") {
            // old offshore data format suplied to tx extra
            LOG_PRINT_L1("Invalid offshore data format was supplied to tx." << id);
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
      } else {
        if (tx_offshore_data != offshore_data.data) {
          // old offshore data format suplied to tx extra
          LOG_PRINT_L1("Tx offshore data doesn't match with the one from tx extra." << id);
          tvc.m_verifivation_failed = true;
          return false;
        }
      }
    }
    
    
    // Check to make sure that only 1 destination is provided if memo data is specified.
    // This is necessary because we shuffle outputs and there is no way to identify which memo data would relate to which destination if multiples were permitted.
    tx_extra_memo memo;
    if (get_memo_from_tx_extra(tx.extra, memo)) {
      if (tx.vout.size() > 2) {
        LOG_PRINT_L1("transaction has memo data and multiple destinations specified - this is not permitted, rejecting.");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }

    // Set the offshore TX type flags
    std::string source = tvc.m_source_asset;
    std::string dest = tvc.m_dest_asset;
    transaction_type tx_type = tvc.m_type;
    // since tvc can be empty for some situations such as "popping blocks",
    // we make sure those vars are populated.
    if (source.empty() || dest.empty() || tx_type == transaction_type::UNSET) {
      if (!get_tx_asset_types(tx, id, source, dest, false)) {
        LOG_PRINT_L1("At least 1 input or 1 output of the tx was invalid." << id);
        tvc.m_verifivation_failed = true;
        if (source.empty()) {
          tvc.m_invalid_input = true;
        }
        if (dest.empty()) {
          tvc.m_invalid_output = true;
        }
        return false;
      }
      if (!get_tx_type(source, dest, tx_type)) {
        LOG_ERROR("At least 1 input or 1 output of the tx was invalid." << id);
        tvc.m_verifivation_failed = true;
        return false;
      }
      // now populate the tvc
      tvc.m_source_asset = source;
      tvc.m_dest_asset = dest;
      tvc.m_type = tx_type;
    }

    // check whether this is a conversion tx.
    if (source != dest) {

      // Block all conversions as of fork 17 till HAVEN2
      if (hf_version >= HF_VERSION_XASSET_FEES_V2 && hf_version < HF_VERSION_HAVEN2) {
        LOG_ERROR("Conversion TXs are not permitted as of fork" << HF_VERSION_XASSET_FEES_V2);
        tvc.m_verifivation_failed = true;
        return false;
      }
      
      // this check is here because of a soft fork that needed to happen due to invalid pr
      if (tx.pricing_record_height > 658500 || m_blockchain.get_nettype() != MAINNET) {

        // get the pr for this tx
        uint64_t current_height = m_blockchain.get_current_blockchain_height();
        if (!tvc.tx_pr_height_verified) { // will only be false if poping blocks
          if (!tx_pr_height_valid(current_height, tx.pricing_record_height, id)) {
            LOG_ERROR("Tx uses older pricing record than what is allowed. Current height: " << current_height << " Pr height: " << tx.pricing_record_height);
            tvc.m_verifivation_failed = true;
            return false;
          } else {
            tvc.tx_pr_height_verified = true;
          }
        }
        if(tvc.pr.empty()) {
          if (tx.pricing_record_height == 821428 && m_blockchain.get_nettype() == MAINNET) {
            tvc.pr.set_for_height_821428();
          } else {
            // Get the pricing record that was used for conversion
            block bl;
            bool r = m_blockchain.get_block_by_hash(m_blockchain.get_block_id_by_height(tx.pricing_record_height), bl);
            if (!r) {
              LOG_ERROR("error: failed to get block containing pricing record");
              tvc.m_verifivation_failed = true;
              return false;
            }
            tvc.pr = bl.pricing_record;
          }
        }

        // check whether we have a valid exchange rate (some values in the pr mioght be 0)
        if (tx_type == transaction_type::OFFSHORE || tx_type == transaction_type::ONSHORE) {
          if (!tvc.pr.ma("XHV")) { // using 24 hr MA in unused1
            LOG_ERROR("error: empty exchange rate. Conversion not possible.");
            tvc.m_verifivation_failed = true;
            return false;
          }
        } else if (tx_type == transaction_type::XUSD_TO_XASSET) {
          if (!tvc.pr.spot(dest)) {
            LOG_ERROR("error: empty exchange rate. Conversion not possible.");
            tvc.m_verifivation_failed = true;
            return false;
          }
        } else if (tx_type == transaction_type::XASSET_TO_XUSD) {
          if (!tvc.pr.spot(source)) {
            LOG_ERROR("error: empty exchange rate. Conversion not possible.");
            tvc.m_verifivation_failed = true;
            return false;
          }
        } else {
          LOG_ERROR("error: wrong tx type set.");
          tvc.m_verifivation_failed = true;
          return false;
        }
        
        // check whether we have empty amount burnt/mint. Actual validation happens in verRctSemanticsSimple()
        if (!tx.amount_burnt || !tx.amount_minted) {
          LOG_ERROR("error: Invalid Tx found. 0 burnt/minted for a conversion tx.");
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Get the conversion rate used
        uint64_t conversion_rate = COIN;
        if (!cryptonote::get_conversion_rate(tvc.pr, source, dest, conversion_rate, hf_version)) {
          LOG_ERROR("error: unable to obtain conversion rate.");
          tvc.m_verifivation_failed = true;
          return false;
        }
      
        // Check the amount burnt and minted
        if (!rct::checkBurntAndMinted(tx.rct_signatures, tx.amount_burnt, tx.amount_minted, tvc.pr, conversion_rate, source, dest, hf_version)) {
          LOG_PRINT_L1("amount burnt / minted is incorrect: burnt = " << tx.amount_burnt << ", minted = " << tx.amount_minted);
          tvc.m_verifivation_failed = true;
          return false;
        }

        // changing tx pricing_record height to current_heihgt might cause sync problems due to at leat 1 block diff between them.
        uint64_t unlock_time = get_tx_unlock_time(tx.unlock_time, tx.pricing_record_height, current_height);
        if (tx_type == transaction_type::OFFSHORE || tx_type == transaction_type::ONSHORE) {
          if (unlock_time < 180) {
            LOG_PRINT_L1("unlock_time is too short: " << unlock_time << " blocks - rejecting (minimum permitted is 180 blocks)");
            tvc.m_verifivation_failed = true;
            return false;
          }
        } else if (tx_type == transaction_type::XASSET_TO_XUSD || tx_type == transaction_type::XUSD_TO_XASSET) {
          if (hf_version >= HF_VERSION_XASSET_FEES_V2) {
            if (unlock_time < 1440) {
              LOG_PRINT_L1("unlock_time is too short: " << unlock_time << " blocks - rejecting (minimum permitted is 1440 blocks for xasset conversions.)");
              tvc.m_verifivation_failed = true;
              return false;
            }
          }
        }

        // validate conversion fees
        uint64_t priority = (unlock_time >= 5040) ? 1 : (unlock_time >= 1440) ? 2 : (unlock_time >= 720) ? 3 : 4;
        uint64_t conversion_fee_check = 0;
        if (tx_type == transaction_type::OFFSHORE || tx_type == transaction_type::ONSHORE) {
          conversion_fee_check = (priority == 1) ? tx.amount_burnt / 500 : (priority == 2) ? tx.amount_burnt / 20 : (priority == 3) ? tx.amount_burnt / 10 : tx.amount_burnt / 5;
        } else if (tx_type == transaction_type::XASSET_TO_XUSD || tx_type == transaction_type::XUSD_TO_XASSET) {
          if (hf_version >= HF_VERSION_XASSET_FEES_V2) {
            // Flat 0.5% conversion fee for xAsset TXs after that fork, plus an adjustment 
            // for the tx.amount_burnt containing the 80% burnt fee proportion as well
            boost::multiprecision::uint128_t amount_128 = tx.amount_burnt;
            amount_128 = (amount_128 * 10) / (2000 + 8);
            conversion_fee_check = (uint64_t)amount_128;
          } else {
            // Flat 0.3% conversion fee for xAsset TXs
            boost::multiprecision::uint128_t amount_128 = tx.amount_burnt;
            amount_128 = (amount_128 * 3) / 1000;
            conversion_fee_check = (uint64_t)(amount_128);
          }
        }

        if (
          ((tx_type == transaction_type::OFFSHORE) && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee)) ||
          ((tx_type == transaction_type::ONSHORE || tx_type == transaction_type::XUSD_TO_XASSET) && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee_usd)) ||
          ((tx_type == transaction_type::XASSET_TO_XUSD) && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee_xasset))
        ){
          // Check for 2 known overflow TXs
          if ((epee::string_tools::pod_to_hex(id) != "5cdd9be420bd9034e2ff83a04cd22978c163a5263f8e7a0577f46ec762a21da6") &&
              (epee::string_tools::pod_to_hex(id) != "b5cd616fc1b64a04750f890e466663ee3308c07846a174daf4d64c111f2de052")) {
          
            LOG_PRINT_L1("conversion fee is incorrect - rejecting");
            tvc.m_verifivation_failed = true;
            tvc.m_fee_too_low = true;
            return false;
          }
        }
      }
    } else {
      // make sure there is no burnt/mint set for transfers, since these numbers will affect circulating supply.
      if (tx.amount_burnt || tx.amount_minted) {
        LOG_ERROR("error: Invalid Tx found. Amount burnt/mint > 0 for a transfer tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }
      // make sure no pr heiht set
      if (hf_version >= HF_VERSION_OFFSHORE_FEES_V2 && tx.pricing_record_height) {
        LOG_ERROR("error: Invalid Tx found. Tx pricing_record_height > 0 for a transfer tx.");
        tvc.m_verifivation_failed = true;
        return false;
      }
    }

    // check the std tx fee
    if (!kept_by_block) {
      if ((!fee && !fee_usd && !fee_xasset) || !m_blockchain.check_fee(tx_weight, source == "XHV" ? fee : source == "XUSD" ? fee_usd : fee_xasset, tvc.pr, source, dest, tx_type)){
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
      }
    }
    
    size_t tx_weight_limit = get_transaction_weight_limit(hf_version);
    if ((!kept_by_block || hf_version >= HF_VERSION_PER_BYTE_FEE) && tx_weight > tx_weight_limit)
    {
      LOG_PRINT_L1("transaction is too heavy: " << tx_weight << " bytes, maximum weight: " << tx_weight_limit);
      tvc.m_verifivation_failed = true;
      tvc.m_too_big = true;
      return false;
    }

    // if the transaction came from a block popped from the chain,
    // don't check if we have its key images as spent.
    // TODO: Investigate why not?
    if(!kept_by_block)
    {
      if(have_tx_keyimges_as_spent(tx, id))
      {
        mark_double_spend(tx);
        LOG_PRINT_L1("Transaction with id= "<< id << " used already spent key images");
        tvc.m_verifivation_failed = true;
        tvc.m_double_spend = true;
        return false;
      }
    }

    if (!m_blockchain.check_tx_outputs(tx, tvc))
    {
      LOG_PRINT_L1("Transaction with id= "<< id << " has at least one invalid output");
      tvc.m_verifivation_failed = true;
      tvc.m_invalid_output = true;
      return false;
    }

    // assume failure during verification steps until success is certain
    tvc.m_verifivation_failed = true;

    time_t receive_time = time(nullptr);

    crypto::hash max_used_block_id = null_hash;
    uint64_t max_used_block_height = 0;
    cryptonote::txpool_tx_meta_t meta{};
    strcpy(meta.fee_asset_type, source.c_str());
    bool ch_inp_res = check_tx_inputs([&tx]()->cryptonote::transaction&{ return tx; }, id, max_used_block_height, max_used_block_id, tvc, kept_by_block);
    if(!ch_inp_res)
    {
      // if the transaction was valid before (kept_by_block), then it
      // may become valid again, so ignore the failed inputs check.
      if(kept_by_block)
      {
        meta.weight = tx_weight;
        if (source == "XHV") {
          meta.fee = fee;
          meta.offshore_fee = offshore_fee;
        } else if (source == "XUSD") {
          meta.fee = fee_usd;
          meta.offshore_fee = offshore_fee_usd;
        } else {
          meta.fee = fee_xasset;
          meta.offshore_fee = offshore_fee_xasset;
        }
        meta.max_used_block_id = null_hash;
        meta.max_used_block_height = 0;
        meta.last_failed_height = 0;
        meta.last_failed_id = null_hash;
        meta.receive_time = receive_time;
        meta.last_relayed_time = time(NULL);
        meta.relayed = relayed;
        meta.set_relay_method(tx_relay);
        meta.double_spend_seen = have_tx_keyimges_as_spent(tx, id);
        meta.pruned = tx.pruned;
        meta.bf_padding = 0;
        memset(meta.padding1, 0, sizeof(meta.padding1));
        memset(meta.padding, 0, sizeof(meta.padding));
        try
        {
          if (kept_by_block)
            m_parsed_tx_cache.insert(std::make_pair(id, tx));
          CRITICAL_REGION_LOCAL1(m_blockchain);
          LockedTXN lock(m_blockchain.get_db());
          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.add_txpool_tx(id, blob, meta);
          m_txs_by_fee_and_receive_time.emplace(std::pair<double, std::time_t>(meta.fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
          lock.commit();
        }
        catch (const std::exception &e)
        {
          MERROR("Error adding transaction to txpool: " << e.what());
          return false;
        }
        tvc.m_verifivation_impossible = true;
        tvc.m_added_to_pool = true;
      }else
      {
        LOG_PRINT_L1("tx used wrong inputs, rejected");
        tvc.m_verifivation_failed = true;
        tvc.m_invalid_input = true;
        return false;
      }
    }else
    {
      try
      {
        if (kept_by_block)
          m_parsed_tx_cache.insert(std::make_pair(id, tx));
        CRITICAL_REGION_LOCAL1(m_blockchain);
        LockedTXN lock(m_blockchain.get_db());

        const bool existing_tx = m_blockchain.get_txpool_tx_meta(id, meta);
        if (existing_tx)
        {
          /* If Dandelion++ loop. Do not use txes in the `local` state in the
             loop detection - txes in that state should be outgoing over i2p/tor
             then routed back via public dandelion++ stem. Pretend to be
             another stem node in that situation, a loop over the public
             network hasn't been hit yet. */
          if (tx_relay == relay_method::stem && meta.dandelionpp_stem)
            tx_relay = relay_method::fluff;
        }
        else
          meta.set_relay_method(relay_method::none);

        if (meta.upgrade_relay_method(tx_relay) || !existing_tx) // synchronize with embargo timer or stem/fluff out-of-order messages
        {
          //update transactions container
          meta.last_relayed_time = std::numeric_limits<decltype(meta.last_relayed_time)>::max();
          meta.receive_time = receive_time;
          meta.weight = tx_weight;
          if (source == "XHV") {
            meta.fee = fee;
            meta.offshore_fee = offshore_fee;
          } else if (source == "XUSD") {
            meta.fee = fee_usd;
            meta.offshore_fee = offshore_fee_usd;
          } else {
            meta.fee = fee_xasset;
            meta.offshore_fee = offshore_fee_xasset;
          }
          meta.max_used_block_id = max_used_block_id;
          meta.max_used_block_height = max_used_block_height;
          meta.last_failed_height = 0;
          meta.last_failed_id = null_hash;
          meta.relayed = relayed;
          meta.double_spend_seen = false;
          meta.pruned = tx.pruned;
          meta.bf_padding = 0;
	        memset(meta.padding1, 0, sizeof(meta.padding1));
          memset(meta.padding, 0, sizeof(meta.padding));

          if (!insert_key_images(tx, id, tx_relay))
            return false;

          m_blockchain.remove_txpool_tx(id);
          m_blockchain.add_txpool_tx(id, blob, meta);
          m_txs_by_fee_and_receive_time.emplace(std::pair<double, std::time_t>(meta.fee / (double)(tx_weight ? tx_weight : 1), receive_time), id);
        }
        lock.commit();
      }
      catch (const std::exception &e)
      {
        MERROR("internal error: error adding transaction to txpool: " << e.what());
        return false;
      }
      tvc.m_added_to_pool = true;

      static_assert(unsigned(relay_method::none) == 0, "expected relay_method::none value to be zero");
      if(meta.fee > 0){
        tvc.m_relay = tx_relay;
      }
    }

    tvc.m_verifivation_failed = false;
    m_txpool_weight += tx_weight;

    ++m_cookie;

    MINFO("Transaction added to pool: txid " << id << " weight: " << tx_weight << " fee/byte: " << (meta.fee / (double)(tx_weight ? tx_weight : 1)) << " " << source);

    prune(m_txpool_max_weight);

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t version)
  {
    crypto::hash h = null_hash;
    cryptonote::blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    if (bl.size() == 0 || !get_transaction_hash(tx, h))
      return false;
    if (version >= HF_VERSION_HAVEN2) {
      return add_tx2(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, tx_relay, relayed, version);
    } else {
      return add_tx(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, tx_relay, relayed, version);
    }
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_txpool_weight() const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    return m_txpool_weight;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_txpool_max_weight(size_t bytes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_txpool_max_weight = bytes;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::reduce_txpool_weight(size_t weight)
  {
    if (weight > m_txpool_weight)
    {
      MERROR("Underflow in txpool weight");
      m_txpool_weight = 0;
    }
    else
    {
      m_txpool_weight -= weight;
    }
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::prune(size_t bytes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    if (bytes == 0)
      bytes = m_txpool_max_weight;
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    bool changed = false;

    // this will never remove the first one, but we don't care
    auto it = --m_txs_by_fee_and_receive_time.end();
    while (it != m_txs_by_fee_and_receive_time.begin())
    {
      if (m_txpool_weight <= bytes)
        break;
      try
      {
        const crypto::hash &txid = it->second;
        txpool_tx_meta_t meta;
        if (!m_blockchain.get_txpool_tx_meta(txid, meta))
        {
          static bool warned = false;
          if (!warned)
          {
            MERROR("Failed to find tx_meta in txpool (will only print once)");
            warned = true;
          }
          --it;
          continue;
        }
        // don't prune the kept_by_block ones, they're likely added because we're adding a block with those
        if (meta.kept_by_block)
        {
          --it;
          continue;
        }
        cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(txid, relay_category::all);
        cryptonote::transaction_prefix tx;
        if (!parse_and_validate_tx_prefix_from_blob(txblob, tx))
        {
          MERROR("Failed to parse tx from txpool");
          return;
        }
        // remove first, in case this throws, so key images aren't removed
        MINFO("Pruning tx " << txid << " from txpool: weight: " << meta.weight << ", fee/byte: " << it->first.first);
        m_blockchain.remove_txpool_tx(txid);
        reduce_txpool_weight(meta.weight);
        remove_transaction_keyimages(tx, txid);
        MINFO("Pruned tx " << txid << " from txpool: weight: " << meta.weight << ", fee/byte: " << it->first.first);
        m_txs_by_fee_and_receive_time.erase(it--);
        changed = true;
      }
      catch (const std::exception &e)
      {
        MERROR("Error while pruning txpool: " << e.what());
        return;
      }
    }
    lock.commit();
    if (changed)
      ++m_cookie;
    if (m_txpool_weight > bytes)
      MINFO("Pool weight after pruning is larger than limit: " << m_txpool_weight << "/" << bytes);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::insert_key_images(const transaction_prefix &tx, const crypto::hash &id, relay_method tx_relay)
  {
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_haven_key, txin, false);
      std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];

      // Only allow multiple txes per key-image if kept-by-block. Only allow
      // the same txid if going from local/stem->fluff.

      if (tx_relay != relay_method::block)
      {
        const bool one_txid =
          (kei_image_set.empty() || (kei_image_set.size() == 1 && *(kei_image_set.cbegin()) == id));
        CHECK_AND_ASSERT_MES(one_txid, false, "internal error: tx_relay=" << unsigned(tx_relay)
                                           << ", kei_image_set.size()=" << kei_image_set.size() << ENDL << "txin.k_image=" << txin.k_image << ENDL
                                           << "tx_id=" << id);
      }

      const bool new_or_previously_private =
        kei_image_set.insert(id).second ||
        !m_blockchain.txpool_tx_matches_category(id, relay_category::legacy);
      CHECK_AND_ASSERT_MES(new_or_previously_private, false, "internal error: try to insert duplicate iterator in key_image set");
    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  //FIXME: Can return early before removal of all of the key images.
  //       At the least, need to make sure that a false return here
  //       is treated properly.  Should probably not return early, however.
  bool tx_memory_pool::remove_transaction_keyimages(const transaction_prefix& tx, const crypto::hash &actual_hash)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    // ND: Speedup
    for(const txin_v& vi: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_haven_key, txin, false);
      auto it = m_spent_key_images.find(txin.k_image);
      CHECK_AND_ASSERT_MES(it != m_spent_key_images.end(), false, "failed to find transaction input in key images. img=" << txin.k_image << ENDL
                                    << "transaction id = " << actual_hash);
      std::unordered_set<crypto::hash>& key_image_set =  it->second;
      CHECK_AND_ASSERT_MES(key_image_set.size(), false, "empty key_image set, img=" << txin.k_image << ENDL
        << "transaction id = " << actual_hash);

      auto it_in_set = key_image_set.find(actual_hash);
      CHECK_AND_ASSERT_MES(it_in_set != key_image_set.end(), false, "transaction id not found in key_image set, img=" << txin.k_image << ENDL
        << "transaction id = " << actual_hash);
      key_image_set.erase(it_in_set);
      if(!key_image_set.size())
      {
        //it is now empty hash container for this key_image
        m_spent_key_images.erase(it);
      }

    }
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::take_tx(const crypto::hash &id, transaction &tx, cryptonote::blobdata &txblob, size_t& tx_weight, uint64_t& fee, uint64_t& offshore_fee, std::string& fee_asset_type, bool &relayed, bool &do_not_relay, bool &double_spend_seen, bool &pruned)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    auto sorted_it = find_tx_in_sorted_container(id);

    try
    {
      LockedTXN lock(m_blockchain.get_db());
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(id, meta))
      {
        MERROR("Failed to find tx_meta in txpool");
        return false;
      }
      txblob = m_blockchain.get_txpool_tx_blob(id, relay_category::all);
      auto ci = m_parsed_tx_cache.find(id);
      if (ci != m_parsed_tx_cache.end())
      {
        tx = ci->second;
      }
      else if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(txblob, tx) : parse_and_validate_tx_from_blob(txblob, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        return false;
      }
      else
      {
        tx.set_hash(id);
      }
      tx_weight = meta.weight;
      fee = meta.fee;
      offshore_fee = meta.offshore_fee;
      fee_asset_type = meta.fee_asset_type;
      relayed = meta.relayed;
      do_not_relay = meta.do_not_relay;
      double_spend_seen = meta.double_spend_seen;
      pruned = meta.pruned;

      // remove first, in case this throws, so key images aren't removed
      m_blockchain.remove_txpool_tx(id);
      m_txpool_weight -= tx_weight;
      remove_transaction_keyimages(tx, id);
      lock.commit();
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to remove tx from txpool: " << e.what());
      return false;
    }

    if (sorted_it != m_txs_by_fee_and_receive_time.end())
      m_txs_by_fee_and_receive_time.erase(sorted_it);
    ++m_cookie;
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction_info(const crypto::hash &txid, tx_details &td) const
  {
    PERF_TIMER(get_transaction_info);
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    try
    {
      LockedTXN lock(m_blockchain.get_db());
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(txid, meta))
      {
        MERROR("Failed to find tx in txpool");
        return false;
      }
      cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(txid, relay_category::all);
      auto ci = m_parsed_tx_cache.find(txid);
      if (ci != m_parsed_tx_cache.end())
      {
        td.tx = ci->second;
      }
      else if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(txblob, td.tx) : parse_and_validate_tx_from_blob(txblob, td.tx)))
      {
        MERROR("Failed to parse tx from txpool");
        return false;
      }
      else
      {
        td.tx.set_hash(txid);
      }
      td.blob_size = txblob.size();
      td.weight = meta.weight;
      td.fee = meta.fee;
      td.max_used_block_id = meta.max_used_block_id;
      td.max_used_block_height = meta.max_used_block_height;
      td.kept_by_block = meta.kept_by_block;
      td.last_failed_height = meta.last_failed_height;
      td.last_failed_id = meta.last_failed_id;
      td.receive_time = meta.receive_time;
      td.last_relayed_time = meta.dandelionpp_stem ? 0 : meta.last_relayed_time;
      td.relayed = meta.relayed;
      td.do_not_relay = meta.do_not_relay;
      td.double_spend_seen = meta.double_spend_seen;
    }
    catch (const std::exception &e)
    {
      MERROR("Failed to get tx from txpool: " << e.what());
      return false;
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_complement(const std::vector<crypto::hash> &hashes, std::vector<cryptonote::blobdata> &txes) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    m_blockchain.for_all_txpool_txes([this, &hashes, &txes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      const auto tx_relay_method = meta.get_relay_method();
      if (tx_relay_method != relay_method::block && tx_relay_method != relay_method::fluff)
        return true;
      const auto i = std::find(hashes.begin(), hashes.end(), txid);
      if (i == hashes.end())
      {
        cryptonote::blobdata bd;
        try
        {
          if (!m_blockchain.get_txpool_tx_blob(txid, bd, cryptonote::relay_category::broadcasted))
          {
            MERROR("Failed to get blob for txpool transaction " << txid);
            return true;
          }
          txes.emplace_back(std::move(bd));
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to get blob for txpool transaction " << txid << ": " << e.what());
          return true;
        }
      }
      return true;
    }, false);
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::on_idle()
  {
    m_remove_stuck_tx_interval.do_call([this](){return remove_stuck_transactions();});
  }
  //---------------------------------------------------------------------------------
  sorted_tx_container::iterator tx_memory_pool::find_tx_in_sorted_container(const crypto::hash& id) const
  {
    return std::find_if( m_txs_by_fee_and_receive_time.begin(), m_txs_by_fee_and_receive_time.end()
                       , [&](const sorted_tx_container::value_type& a){
                         return a.second == id;
                       }
    );
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::remove_stuck_transactions()
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    std::list<std::pair<crypto::hash, uint64_t>> remove;
    m_blockchain.for_all_txpool_txes([this, &remove](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      uint64_t tx_age = time(nullptr) - meta.receive_time;
      bool has_conv_fee = (meta.offshore_fee > 0);

      if((tx_age > CRYPTONOTE_MEMPOOL_TX_LIVETIME && !meta.kept_by_block) ||
         (tx_age > CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME && meta.kept_by_block) || 
         (has_conv_fee && tx_age > CRYPTONOTE_MEMPOOL_TX_CONVERSION_LIVETIME && !meta.kept_by_block)) //Remove conversions faster, as their pricing record is outdated
      {
        LOG_PRINT_L1("Tx " << txid << " removed from tx pool due to outdated, age: " << tx_age );
        auto sorted_it = find_tx_in_sorted_container(txid);
        if (sorted_it == m_txs_by_fee_and_receive_time.end())
        {
          LOG_PRINT_L1("Removing tx " << txid << " from tx pool, but it was not found in the sorted txs container!");
        }
        else
        {
          m_txs_by_fee_and_receive_time.erase(sorted_it);
        }
        m_timed_out_transactions.insert(txid);
        remove.push_back(std::make_pair(txid, meta.weight));
      }
      return true;
    }, false, relay_category::all);

    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const std::pair<crypto::hash, uint64_t> &entry: remove)
      {
        const crypto::hash &txid = entry.first;
        try
        {
          cryptonote::blobdata bd = m_blockchain.get_txpool_tx_blob(txid, relay_category::all);
          cryptonote::transaction_prefix tx;
          if (!parse_and_validate_tx_prefix_from_blob(bd, tx))
          {
            MERROR("Failed to parse tx from txpool");
            // continue
          }
          else
          {
            // remove first, so we only remove key images if the tx removal succeeds
            m_blockchain.remove_txpool_tx(txid);
            reduce_txpool_weight(entry.second);
            remove_transaction_keyimages(tx, txid);
          }
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove stuck transaction: " << txid);
          // ignore error
        }
      }
      lock.commit();
      ++m_cookie;
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_relayable_transactions(std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> &txs)
  {
    using clock = std::chrono::system_clock;

    const uint64_t now = time(NULL);
    if (uint64_t{std::numeric_limits<time_t>::max()} < now || time_t(now) < m_next_check)
      return false;

    uint64_t next_check = clock::to_time_t(clock::from_time_t(time_t(now)) + max_relayable_check);
    std::vector<std::pair<crypto::hash, txpool_tx_meta_t>> change_timestamps;

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    txs.reserve(m_blockchain.get_txpool_tx_count());
    m_blockchain.for_all_txpool_txes([this, now, &txs, &change_timestamps, &next_check](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *){
      // 0 fee transactions are never relayed
      if(!meta.pruned && meta.fee > 0 && !meta.do_not_relay)
      {
        const relay_method tx_relay = meta.get_relay_method();
        switch (tx_relay)
        {
          case relay_method::stem:
          case relay_method::forward:
            if (meta.last_relayed_time > now)
            {
              next_check = std::min(next_check, meta.last_relayed_time);
              return true; // continue to next tx
            }
            change_timestamps.emplace_back(txid, meta);
            break;
          default:
          case relay_method::none:
            return true;
          case relay_method::local:
          case relay_method::fluff:
          case relay_method::block:
            if (now - meta.last_relayed_time <= get_relay_delay(meta.last_relayed_time, meta.receive_time))
              return true; // continue to next tx
            break;
        }

        // if the tx is older than half the max lifetime, we don't re-relay it, to avoid a problem
        // mentioned by smooth where nodes would flush txes at slightly different times, causing
        // flushed txes to be re-added when received from a node which was just about to flush it
        uint64_t max_age = (tx_relay == relay_method::block) ? CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME : CRYPTONOTE_MEMPOOL_TX_LIVETIME;
        if (now - meta.receive_time <= max_age / 2)
        {
          try
          {
            txs.emplace_back(txid, m_blockchain.get_txpool_tx_blob(txid, relay_category::all), tx_relay);
          }
          catch (const std::exception &e)
          {
            MERROR("Failed to get transaction blob from db");
            // ignore error
          }
        }
      }
      return true;
    }, false, relay_category::relayable);

    for (auto& elem : change_timestamps)
    {
      /* These transactions are still in forward or stem state, so the field
         represents the next time a relay should be attempted. Will be
         overwritten when the state is upgraded to stem, fluff or block. This
         function is only called every ~2 minutes, so this resetting should be
         unnecessary, but is primarily a precaution against potential changes
	 to the callback routines. */
      elem.second.last_relayed_time = now + get_relay_delay(elem.second.last_relayed_time, elem.second.receive_time);
      m_blockchain.update_txpool_tx(elem.first, elem.second);
    }

    m_next_check = time_t(next_check);
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_relayed(const epee::span<const crypto::hash> hashes, const relay_method method, std::vector<bool> &just_broadcasted)
  {
    just_broadcasted.clear();

    crypto::random_poisson_seconds embargo_duration{dandelionpp_embargo_average};
    const auto now = std::chrono::system_clock::now();
    uint64_t next_relay = uint64_t{std::numeric_limits<time_t>::max()};

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    for (const auto& hash : hashes)
    {
      bool was_just_broadcasted = false;
      try
      {
        txpool_tx_meta_t meta;
        if (m_blockchain.get_txpool_tx_meta(hash, meta))
        {
          // txes can be received as "stem" or "fluff" in either order
          const bool already_broadcasted = meta.matches(relay_category::broadcasted);
          meta.upgrade_relay_method(method);
          meta.relayed = true;

          if (meta.dandelionpp_stem)
          {
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now + embargo_duration());
            next_relay = std::min(next_relay, meta.last_relayed_time);
          }
          else
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now);

          m_blockchain.update_txpool_tx(hash, meta);

          // wait until db update succeeds to ensure tx is visible in the pool
          was_just_broadcasted = !already_broadcasted && meta.matches(relay_category::broadcasted);
        }
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to update txpool transaction metadata: " << e.what());
        // continue
      }
      just_broadcasted.emplace_back(was_just_broadcasted);
    }
    lock.commit();
    set_if_less(m_next_check, time_t(next_relay));
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::get_transactions_count(bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    return m_blockchain.get_txpool_tx_count(include_sensitive);
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::get_transactions(std::vector<transaction>& txs, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    txs.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      transaction tx;
      if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*bd, tx) : parse_and_validate_tx_from_blob(*bd, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx.set_hash(txid);
      txs.push_back(std::move(tx));
      return true;
    }, true, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_hashes(std::vector<crypto::hash>& txs, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    txs.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      txs.push_back(txid);
      return true;
    }, false, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_backlog(std::vector<tx_backlog_entry>& backlog, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const uint64_t now = time(NULL);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    backlog.reserve(m_blockchain.get_txpool_tx_count(include_sensitive));
    m_blockchain.for_all_txpool_txes([&backlog, now](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      backlog.push_back({meta.weight, meta.fee, meta.receive_time - now});
      return true;
    }, false, category);
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_block_template_backlog(std::vector<tx_block_template_backlog_entry>& backlog, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    std::vector<tx_block_template_backlog_entry> tmp;
    uint64_t total_weight = 0;

    // First get everything from the mempool, filter it later
    m_blockchain.for_all_txpool_txes([&tmp, &total_weight](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*){
      tmp.emplace_back(tx_block_template_backlog_entry{txid, meta.weight, meta.fee});
      total_weight += meta.weight;
      return true;
    }, false, include_sensitive ? relay_category::all : relay_category::broadcasted);

    // Limit backlog to 112.5% of current median weight. This is enough to mine a full block with the optimal block reward
    const uint64_t median_weight = m_blockchain.get_current_cumulative_block_weight_median();
    const uint64_t max_backlog_weight = median_weight + (median_weight / 8);

    // If the total weight is too high, choose the best paying transactions
    if (total_weight > max_backlog_weight)
      std::sort(tmp.begin(), tmp.end(), [](const auto& a, const auto& b){ return a.fee * b.weight > b.fee * a.weight; });

    backlog.clear();
    uint64_t w = 0;

    std::unordered_set<crypto::key_image> k_images;

    for (const tx_block_template_backlog_entry& e : tmp)
    {
      try
      {
        txpool_tx_meta_t meta;
        if (!m_blockchain.get_txpool_tx_meta(e.id, meta))
          continue;

        cryptonote::blobdata txblob;
        if (!m_blockchain.get_txpool_tx_blob(e.id, txblob, relay_category::all))
          continue;

        cryptonote::transaction tx;
        if (is_transaction_ready_to_go(meta, e.id, txblob, tx))
        {
          if (have_key_images(k_images, tx))
            continue;
          append_key_images(k_images, tx);

          backlog.push_back(e);
          w += e.weight;
          if (w > max_backlog_weight)
            break;
        }
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to check transaction readiness: " << e.what());
        // continue, not fatal
      }
    }
  }
  //------------------------------------------------------------------
  void tx_memory_pool::get_transaction_stats(struct txpool_stats& stats, bool include_sensitive) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const uint64_t now = time(NULL);
    const relay_category category = include_sensitive ? relay_category::all : relay_category::broadcasted;
    std::map<uint64_t, txpool_histo> agebytes;
    stats.txs_total = m_blockchain.get_txpool_tx_count(include_sensitive);
    std::vector<uint32_t> weights;
    weights.reserve(stats.txs_total);
    m_blockchain.for_all_txpool_txes([&stats, &weights, now, &agebytes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      weights.push_back(meta.weight);
      stats.bytes_total += meta.weight;
      if (!stats.bytes_min || meta.weight < stats.bytes_min)
        stats.bytes_min = meta.weight;
      if (meta.weight > stats.bytes_max)
        stats.bytes_max = meta.weight;
      if (!meta.relayed)
        stats.num_not_relayed++;
      stats.fee_total += meta.fee;
      if (!stats.oldest || meta.receive_time < stats.oldest)
        stats.oldest = meta.receive_time;
      if (meta.receive_time < now - 600)
        stats.num_10m++;
      if (meta.last_failed_height)
        stats.num_failing++;
      uint64_t age = now - meta.receive_time + (now == meta.receive_time);
      agebytes[age].txs++;
      agebytes[age].bytes += meta.weight;
      if (meta.double_spend_seen)
        ++stats.num_double_spends;
      return true;
    }, false, category);

    stats.bytes_med = epee::misc_utils::median(weights);
    if (stats.txs_total > 1)
    {
      /* looking for 98th percentile */
      size_t end = stats.txs_total * 0.02;
      uint64_t delta, factor;
      std::map<uint64_t, txpool_histo>::iterator it, i2;
      if (end)
      {
        /* If enough txs, spread the first 98% of results across
         * the first 9 bins, drop final 2% in last bin.
         */
        it = agebytes.end();
        size_t cumulative_num = 0;
        /* Since agebytes is not empty and end is nonzero, the
         * below loop can always run at least once.
         */
        do {
          --it;
          cumulative_num += it->second.txs;
        } while (it != agebytes.begin() && cumulative_num < end);
        stats.histo_98pc = it->first;
        factor = 9;
        delta = it->first;
        stats.histo.resize(10);
      } else
      {
        /* If not enough txs, don't reserve the last slot;
         * spread evenly across all 10 bins.
         */
        stats.histo_98pc = 0;
        it = agebytes.end();
        factor = stats.txs_total > 9 ? 10 : stats.txs_total;
        delta = now - stats.oldest;
        stats.histo.resize(factor);
      }
      if (!delta)
        delta = 1;
      for (i2 = agebytes.begin(); i2 != it; i2++)
      {
        size_t i = (i2->first * factor - 1) / delta;
        stats.histo[i].txs += i2->second.txs;
        stats.histo[i].bytes += i2->second.bytes;
      }
      for (; i2 != agebytes.end(); i2++)
      {
        stats.histo[factor].txs += i2->second.txs;
        stats.histo[factor].bytes += i2->second.bytes;
      }
    }
  }
  //------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::get_transactions_and_spent_keys_info(std::vector<tx_info>& tx_infos, std::vector<spent_key_image_info>& key_image_infos, bool include_sensitive_data) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const relay_category category = include_sensitive_data ? relay_category::all : relay_category::broadcasted;
    const size_t count = m_blockchain.get_txpool_tx_count(include_sensitive_data);
    tx_infos.reserve(count);
    key_image_infos.reserve(count);
    m_blockchain.for_all_txpool_txes([&tx_infos, key_image_infos, include_sensitive_data](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      tx_info txi;
      txi.id_hash = epee::string_tools::pod_to_hex(txid);
      txi.tx_blob = blobdata(bd->data(), bd->size());
      transaction tx;
      if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*bd, tx) : parse_and_validate_tx_from_blob(*bd, tx)))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      tx.set_hash(txid);
      txi.tx_json = obj_to_json_str(tx);
      txi.blob_size = bd->size();
      txi.weight = meta.weight;
      txi.fee = meta.fee;
      txi.kept_by_block = meta.kept_by_block;
      txi.max_used_block_height = meta.max_used_block_height;
      txi.max_used_block_id_hash = epee::string_tools::pod_to_hex(meta.max_used_block_id);
      txi.last_failed_height = meta.last_failed_height;
      txi.last_failed_id_hash = epee::string_tools::pod_to_hex(meta.last_failed_id);
      // In restricted mode we do not include this data:
      txi.receive_time = include_sensitive_data ? meta.receive_time : 0;
      txi.relayed = meta.relayed;
      // In restricted mode we do not include this data:
      txi.last_relayed_time = (include_sensitive_data && !meta.dandelionpp_stem) ? meta.last_relayed_time : 0;
      txi.do_not_relay = meta.do_not_relay;
      txi.double_spend_seen = meta.double_spend_seen;
      tx_infos.push_back(std::move(txi));
      return true;
    }, true, category);

    for (const key_images_container::value_type& kee : m_spent_key_images) {
      const crypto::key_image& k_image = kee.first;
      const std::unordered_set<crypto::hash>& kei_image_set = kee.second;
      spent_key_image_info ki;
      ki.id_hash = epee::string_tools::pod_to_hex(k_image);
      for (const crypto::hash& tx_id_hash : kei_image_set)
      {
        if (m_blockchain.txpool_tx_matches_category(tx_id_hash, category))
          ki.txs_hashes.push_back(epee::string_tools::pod_to_hex(tx_id_hash));
      }

      // Only return key images for which we have at least one tx that we can show for them
      if (!ki.txs_hashes.empty())
        key_image_infos.push_back(std::move(ki));
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_pool_for_rpc(std::vector<cryptonote::rpc::tx_in_pool>& tx_infos, cryptonote::rpc::key_images_with_tx_hashes& key_image_infos) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    tx_infos.reserve(m_blockchain.get_txpool_tx_count());
    key_image_infos.reserve(m_blockchain.get_txpool_tx_count());
    m_blockchain.for_all_txpool_txes([&tx_infos, key_image_infos](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd){
      cryptonote::rpc::tx_in_pool txi;
      txi.tx_hash = txid;
      if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*bd, txi.tx) : parse_and_validate_tx_from_blob(*bd, txi.tx)))
      {
        MERROR("Failed to parse tx from txpool");
        // continue
        return true;
      }
      txi.tx.set_hash(txid);
      txi.blob_size = bd->size();
      txi.weight = meta.weight;
      txi.fee = meta.fee;
      txi.kept_by_block = meta.kept_by_block;
      txi.max_used_block_height = meta.max_used_block_height;
      txi.max_used_block_hash = meta.max_used_block_id;
      txi.last_failed_block_height = meta.last_failed_height;
      txi.last_failed_block_hash = meta.last_failed_id;
      txi.receive_time = meta.receive_time;
      txi.relayed = meta.relayed;
      txi.last_relayed_time = meta.dandelionpp_stem ? 0 : meta.last_relayed_time;
      txi.do_not_relay = meta.do_not_relay;
      txi.double_spend_seen = meta.double_spend_seen;
      tx_infos.push_back(txi);
      return true;
    }, true, relay_category::broadcasted);

    for (const key_images_container::value_type& kee : m_spent_key_images) {
      std::vector<crypto::hash> tx_hashes;
      const std::unordered_set<crypto::hash>& kei_image_set = kee.second;
      for (const crypto::hash& tx_id_hash : kei_image_set)
      {
        if (m_blockchain.txpool_tx_matches_category(tx_id_hash, relay_category::broadcasted))
          tx_hashes.push_back(tx_id_hash);
      }

      if (!tx_hashes.empty())
        key_image_infos[kee.first] = std::move(tx_hashes);
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::check_for_key_images(const std::vector<crypto::key_image>& key_images, std::vector<bool>& spent) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    spent.clear();

    for (const auto& image : key_images)
    {
      bool is_spent = false;
      const auto found = m_spent_key_images.find(image);
      if (found != m_spent_key_images.end())
      {
        for (const crypto::hash& tx_hash : found->second)
          is_spent |= m_blockchain.txpool_tx_matches_category(tx_hash, relay_category::broadcasted);
      }
      spent.push_back(is_spent);
    }

    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::get_transaction(const crypto::hash& id, cryptonote::blobdata& txblob, relay_category tx_category) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    try
    {
      return m_blockchain.get_txpool_tx_blob(id, txblob, tx_category);
    }
    catch (const std::exception &e)
    {
      return false;
    }
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_inc(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_input_cache.clear();
    m_parsed_tx_cache.clear();
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::on_blockchain_dec(uint64_t new_block_height, const crypto::hash& top_block_id)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    m_input_cache.clear();
    m_parsed_tx_cache.clear();
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx(const crypto::hash &id, relay_category tx_category) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    return m_blockchain.get_db().txpool_has_tx(id, tx_category);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimges_as_spent(const transaction& tx, const crypto::hash& txid) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    for(const auto& in: tx.vin)
    {
      CHECKED_GET_SPECIFIC_VARIANT(in, const txin_haven_key, tokey_in, true);//should never fail
      if(have_tx_keyimg_as_spent(tokey_in.k_image, txid))
         return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_tx_keyimg_as_spent(const crypto::key_image& key_im, const crypto::hash& txid) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    const auto found = m_spent_key_images.find(key_im);
    if (found != m_spent_key_images.end() && !found->second.empty())
    {
      // If another tx is using the key image, always return as spent.
      // See `insert_key_images`.
      if (1 < found->second.size() || *(found->second.cbegin()) != txid)
        return true;
      return m_blockchain.txpool_tx_matches_category(txid, relay_category::legacy);
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::lock() const
  {
    m_transactions_lock.lock();
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::unlock() const
  {
    m_transactions_lock.unlock();
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::check_tx_inputs(const std::function<cryptonote::transaction&(void)> &get_tx, const crypto::hash &txid, uint64_t &max_used_block_height, crypto::hash &max_used_block_id, tx_verification_context &tvc, bool kept_by_block) const
  {
    if (!kept_by_block)
    {
      const std::unordered_map<crypto::hash, std::tuple<bool, tx_verification_context, uint64_t, crypto::hash>>::const_iterator i = m_input_cache.find(txid);
      if (i != m_input_cache.end())
      {
        max_used_block_height = std::get<2>(i->second);
        max_used_block_id = std::get<3>(i->second);
        tvc = std::get<1>(i->second);
        return std::get<0>(i->second);
      }
    }

    transaction tx=get_tx();
    bool ret = m_blockchain.check_tx_inputs(tx, max_used_block_height, max_used_block_id, tvc, kept_by_block);
    uint64_t hf_version=m_blockchain.get_current_hard_fork_version();
    uint64_t current_height=m_blockchain.get_current_blockchain_height();
    // Get the TX anonymity pool
    anonymity_pool tx_anon_pool=anonymity_pool::UNSET;

    if (hf_version>=HF_VERSION_BURN && current_height >= SUPPLY_AUDIT_ANON_POOL_CHECK_HEIGHT) {
      std::vector<std::vector<output_data_t>> tx_ring_outputs;
      tx_ring_outputs.reserve(tx.vin.size());
      
      for (const txin_v& txin: tx.vin){
        std::vector<output_data_t> ring_outputs;
        if (txin.type() == typeid(txin_haven_key)){
          txin_haven_key tx_input=boost::get<txin_haven_key>(txin);
          std::vector<uint64_t> absolute_offsets = relative_output_offsets_to_absolute(tx_input.key_offsets);
          if (absolute_offsets.size()!=tx_input.key_offsets.size()){
            LOG_ERROR("Failed to obtain absolute ring offsets! amount = " << tx_input.amount);
            ret = false;
          }
          try{
            m_blockchain.get_output_key(epee::span<const uint64_t>(&tx_input.amount, 1), absolute_offsets, ring_outputs, true);
            if (absolute_offsets.size() != ring_outputs.size()){
              LOG_ERROR("Output does not exist! amount = " << tx_input.amount);
              ret = false;
            }
          }
          catch (...){
            LOG_ERROR("Output does not exist! amount = " << tx_input.amount);
            ret = false;
          }
          tx_ring_outputs.push_back(ring_outputs);
        } else if (txin.type() == typeid(txin_gen)){
          tx_ring_outputs.push_back(ring_outputs);
        } else {
          LOG_ERROR("Unexpected input type for transaction" << txid);
          ret=false;
        }
      }

      if (tx_ring_outputs.size()!=tx.vin.size()){
        LOG_ERROR("Transaction has more inputs than number of ring member groups: " << txid);
        ret=false;   
      }

      if(!get_anonymity_pool(tx, tx_ring_outputs, tx_anon_pool, m_blockchain.get_nettype())){
        LOG_ERROR("Failed to get the anonymity pool for transaction " << txid);
        ret=false;   
      }

      if(tx_anon_pool==anonymity_pool::UNSET){
        LOG_ERROR("Failed to get the anonymity pool (has value UNSET) for transaction " << txid);
        ret=false;   
      }
    } else if (hf_version<HF_VERSION_BURN || current_height <= SUPPLY_AUDIT_ANON_POOL_CHECK_HEIGHT){
      tx_anon_pool=anonymity_pool::NOTAPPLICABLE;
    } else {
      //This should not happen
      LOG_ERROR("Failed to assign the anonymity pool" << txid);
      ret=false;   
    }
    tvc.m_tx_anon_pool=tx_anon_pool;
    
    if (!kept_by_block)
      m_input_cache.insert(std::make_pair(txid, std::make_tuple(ret, tvc, max_used_block_height, max_used_block_id)));
    return ret;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::is_transaction_ready_to_go(txpool_tx_meta_t& txd, const crypto::hash &txid, const cryptonote::blobdata_ref& txblob, transaction &tx) const
  {
    struct transaction_parser
    {
      transaction_parser(const cryptonote::blobdata_ref &txblob, const crypto::hash &txid, transaction &tx): txblob(txblob), txid(txid), tx(tx), parsed(false) {}
      cryptonote::transaction &operator()()
      {
        if (!parsed)
        {
          if (!parse_and_validate_tx_from_blob(txblob, tx))
            throw std::runtime_error("failed to parse transaction blob");
          tx.set_hash(txid);
          parsed = true;
        }
        return tx;
      }
      const cryptonote::blobdata_ref &txblob;
      const crypto::hash &txid;
      transaction &tx;
      bool parsed;
    } lazy_tx(txblob, txid, tx);

    //not the best implementation at this time, sorry :(
    //check is ring_signature already checked ?
    if(txd.max_used_block_id == null_hash)
    {//not checked, lets try to check

      if(txd.last_failed_id != null_hash && m_blockchain.get_current_blockchain_height() > txd.last_failed_height && txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
        return false;//we already sure that this tx is broken for this height

      tx_verification_context tvc;
      if(!check_tx_inputs([&lazy_tx]()->cryptonote::transaction&{ return lazy_tx(); }, txid, txd.max_used_block_height, txd.max_used_block_id, tvc))
      {
        txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
        txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
        return false;
      }
    }else
    {
      if(txd.max_used_block_height >= m_blockchain.get_current_blockchain_height())
        return false;
      if(true)
      {
        //if we already failed on this height and id, skip actual ring signature check
        if(txd.last_failed_id == m_blockchain.get_block_id_by_height(txd.last_failed_height))
          return false;
        //check ring signature again, it is possible (with very small chance) that this transaction become again valid
        tx_verification_context tvc;
        if(!check_tx_inputs([&lazy_tx]()->cryptonote::transaction&{ return lazy_tx(); }, txid, txd.max_used_block_height, txd.max_used_block_id, tvc))
        {
          txd.last_failed_height = m_blockchain.get_current_blockchain_height()-1;
          txd.last_failed_id = m_blockchain.get_block_id_by_height(txd.last_failed_height);
          return false;
        }
      }
    }
    //if we here, transaction seems valid, but, anyway, check for key_images collisions with blockchain, just to be sure
    if(m_blockchain.have_tx_keyimges_as_spent(lazy_tx()))
    {
      txd.double_spend_seen = true;
      return false;
    }

    //transaction is ok.
    return true;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::is_transaction_ready_to_go(txpool_tx_meta_t& txd, const crypto::hash &txid, const cryptonote::blobdata& txblob, transaction &tx) const
  {
    return is_transaction_ready_to_go(txd, txid, cryptonote::blobdata_ref{txblob.data(), txblob.size()}, tx);
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::have_key_images(const std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_haven_key, itk, false);
      if(k_images.count(itk.k_image))
        return true;
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::append_key_images(std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_haven_key, itk, false);
      auto i_res = k_images.insert(itk.k_image);
      CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
    }
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::mark_double_spend(const transaction &tx)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    bool changed = false;
    LockedTXN lock(m_blockchain.get_db());
    for(size_t i = 0; i!= tx.vin.size(); i++)
    {
      CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_haven_key, itk, void());
      const key_images_container::const_iterator it = m_spent_key_images.find(itk.k_image);
      if (it != m_spent_key_images.end())
      {
        for (const crypto::hash &txid: it->second)
        {
          txpool_tx_meta_t meta;
          if (!m_blockchain.get_txpool_tx_meta(txid, meta))
          {
            MERROR("Failed to find tx meta in txpool");
            // continue, not fatal
            continue;
          }
          if (!meta.double_spend_seen)
          {
            MDEBUG("Marking " << txid << " as double spending " << itk.k_image);
            meta.double_spend_seen = true;
            changed = true;
            try
            {
              m_blockchain.update_txpool_tx(txid, meta);
            }
            catch (const std::exception &e)
            {
              MERROR("Failed to update tx meta: " << e.what());
              // continue, not fatal
            }
          }
        }
      }
    }
    lock.commit();
    if (changed)
      ++m_cookie;
  }
  //---------------------------------------------------------------------------------
  std::string tx_memory_pool::print_pool(bool short_format) const
  {
    std::stringstream ss;
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    m_blockchain.for_all_txpool_txes([&ss, short_format](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *txblob) {
      ss << "id: " << txid << std::endl;
      if (!short_format) {
        cryptonote::transaction tx;
        if (!(meta.pruned ? parse_and_validate_tx_base_from_blob(*txblob, tx) : parse_and_validate_tx_from_blob(*txblob, tx)))
        {
          MERROR("Failed to parse tx from txpool");
          return true; // continue
        }
        ss << obj_to_json_str(tx) << std::endl;
      }
      ss << "blob_size: " << (short_format ? "-" : std::to_string(txblob->size())) << std::endl
        << "weight: " << meta.weight << std::endl
        << "fee: " << print_money(meta.fee) << std::endl
        << "kept_by_block: " << (meta.kept_by_block ? 'T' : 'F') << std::endl
        << "is_local" << (meta.is_local ? 'T' : 'F') << std::endl
        << "double_spend_seen: " << (meta.double_spend_seen ? 'T' : 'F') << std::endl
        << "max_used_block_height: " << meta.max_used_block_height << std::endl
        << "max_used_block_id: " << meta.max_used_block_id << std::endl
        << "last_failed_height: " << meta.last_failed_height << std::endl
        << "last_failed_id: " << meta.last_failed_id << std::endl;
      return true;
    }, !short_format, relay_category::all);

    return ss.str();
  }
  //---------------------------------------------------------------------------------
  //TODO: investigate whether boolean return is appropriate
  bool tx_memory_pool::fill_block_template(
    block &bl,
    size_t median_weight,
    uint64_t already_generated_coins,
    size_t &total_weight,
    std::map<std::string, uint64_t> &fee_map,
    std::map<std::string, uint64_t> &offshore_fee_map,
    std::map<std::string, uint64_t> &xasset_fee_map,
    uint64_t &expected_reward,
    uint8_t hf_version
  ){

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    using tt = cryptonote::transaction_type;

    uint64_t best_coinbase = 0, coinbase = 0;
    total_weight = 0;
    
    // this holds the total fee amount in XHV for calculation of block reward. 
    // All fees collected in other assets(both regular & conversion fees)
    // is converted and added this.
    uint64_t total_fee_xhv = 0;
    
    //baseline empty block
    if (!get_block_reward(median_weight, total_weight, already_generated_coins, best_coinbase, hf_version))
    {
      MERROR("Failed to get block reward for empty block");
      return false;
    }

    size_t max_total_weight_pre_v5 = (130 * median_weight) / 100 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    size_t max_total_weight_v5 = 2 * median_weight - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    size_t max_total_weight = hf_version >= 5 ? max_total_weight_v5 : max_total_weight_pre_v5;
    std::unordered_set<crypto::key_image> k_images;

    LOG_PRINT_L2("Filling block template, median weight " << median_weight << ", " << m_txs_by_fee_and_receive_time.size() << " txes in the pool");

    LockedTXN lock(m_blockchain.get_db());

    // grap the latest pricing record for conversion of fee values and block cap calculation.
    // ignore the fee converison and block conversions if we fail.
    bool have_valid_pr = true;
    offshore::pricing_record latest_pr;
    if (!m_blockchain.get_latest_acceptable_pr(latest_pr)) {
      if (hf_version >= HF_VERSION_USE_COLLATERAL) {
        MWARNING("Failed to find a pricing record in last 10 block.");
        MWARNING("Tx/conversion fees wont be converted. Cant calculuate block cap. Conversion txs wont be included in the block.");
      }
      have_valid_pr = false;
    }

    // set the block cap
    const std::vector<std::pair<std::string, std::string>>& supply_amounts = m_blockchain.get_db().get_circulating_supply();
    uint64_t block_cap_xhv = get_block_cap(supply_amounts, latest_pr, hf_version);
    uint64_t total_conversion_xhv = 0; // only offshore/onshroe
    MINFO("Block cap limit for offshore/onshore " << block_cap_xhv << " XHV");

    auto sorted_it = m_txs_by_fee_and_receive_time.begin();
    for (; sorted_it != m_txs_by_fee_and_receive_time.end(); ++sorted_it)
    {
      txpool_tx_meta_t meta;
      if (!m_blockchain.get_txpool_tx_meta(sorted_it->second, meta))
      {
        MERROR("  failed to find tx meta");
        continue;
      }
      LOG_PRINT_L2("Considering " << sorted_it->second << ", weight " << meta.weight << ", current block weight " << total_weight << "/" << max_total_weight << ", current coinbase " << print_money(best_coinbase) << ", relay method " << (unsigned)meta.get_relay_method());

      if (!meta.matches(relay_category::legacy) && !(m_mine_stem_txes && meta.get_relay_method() == relay_method::stem))
      {
        LOG_PRINT_L2("  tx relay method is " << (unsigned)meta.get_relay_method());
        // HERE BE DRAGONS!!!
        //continue;
        // LAND AHOY!!!
      }
      if (meta.pruned)
      {
        LOG_PRINT_L2("  tx is pruned");
        continue;
      }

      // Can not exceed maximum block weight
      if (max_total_weight < total_weight + meta.weight)
      {
        LOG_PRINT_L2("  would exceed maximum block weight");
        continue;
      }

      // start using the optimal filling algorithm from v5
      uint64_t total_fee_this_tx_xhv = 0;
      if (hf_version >= 5)
      {
        // If we're getting lower coinbase tx,
        // stop including more tx
        uint64_t block_reward;
        if(!get_block_reward(median_weight, total_weight + meta.weight, already_generated_coins, block_reward, hf_version))
        {
          LOG_PRINT_L2("  would exceed maximum block weight");
          continue;
        }

        // have_valid_pr flag has to be there because if true, that means
        // fee/byte(sorted_it->first.first) value has to be in xhv as calculated
        // when adding the tx into the pool in add_tx2(). if have_valid_pr is false,
        // there shouldnt be any conversion tx anyways, which then means sorting happened on the meta.fee only,
        // and small differences in the tx fee shouldnt matter much. so we can just assume they are all xhv.
        if (hf_version >= HF_VERSION_USE_COLLATERAL) {
          if (have_valid_pr) {
            total_fee_this_tx_xhv = meta.weight * sorted_it->first.first; 
          } else {
            total_fee_this_tx_xhv =  meta.fee + meta.offshore_fee;
          }
          coinbase = block_reward + total_fee_xhv + total_fee_this_tx_xhv;
        } else {
          if (strcmp(meta.fee_asset_type, "XHV") == 0) {
            coinbase = block_reward + fee_map["XHV"] + meta.fee;
          } else {
            coinbase = block_reward + fee_map["XHV"];
          }
        }
        if (coinbase < best_coinbase)
        {
          LOG_PRINT_L2("  would decrease coinbase to " << print_money(coinbase));
          continue;
        }
      }
      else
      {
        // If we've exceeded the penalty free weight,
        // stop including more tx
        if (total_weight > median_weight)
        {
          LOG_PRINT_L2("  would exceed median block weight");
          break;
        }
      }

      // "local" and "stem" txes are filtered above
      cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(sorted_it->second, relay_category::all);

      cryptonote::transaction tx;

      // Skip transactions that are not ready to be
      // included into the blockchain or that are
      // missing key images
      const cryptonote::txpool_tx_meta_t original_meta = meta;
      bool ready = false;
      try
      {
        ready = is_transaction_ready_to_go(meta, sorted_it->second, txblob, tx);
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to check transaction readiness: " << e.what());
        // continue, not fatal
      }
      if (memcmp(&original_meta, &meta, sizeof(meta)))
      {
        try
        {
          m_blockchain.update_txpool_tx(sorted_it->second, meta);
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to update tx meta: " << e.what());
          // continue, not fatal
        }
      }
      if (!ready)
      {
        LOG_PRINT_L2("  not ready to go");
        continue;
      }
      if (have_key_images(k_images, tx))
      {
        LOG_PRINT_L2("  key images already seen");
        continue;
      }

      // get the asset types
      std::string source;
      std::string dest;
      tt tx_type;
      if (!get_tx_asset_types(tx, sorted_it->second, source, dest, false)) {
        LOG_PRINT_L2("At least 1 input or 1 output of the tx was invalid.");
        continue;
      }
      if (!get_tx_type(source, dest, tx_type)) {
        LOG_PRINT_L2(" transaction has invalid tx type " << sorted_it->second);
        continue;
      }

      tx_verification_context tvc;

      
      if(!check_tx_inputs([&tx]()->cryptonote::transaction&{ return tx; }, sorted_it->second, meta.max_used_block_height, meta.max_used_block_id, tvc, meta.kept_by_block))
      {
        LOG_PRINT_L2(" transaction has invalid inputs or anonymity pool " << sorted_it->second);
        continue;
      }
      
      uint64_t conversion_this_tx_xhv = 0;
      if (source != dest)
      {
        // check for block cap limit
        if (hf_version >= HF_VERSION_USE_COLLATERAL && (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE)) {

          // dont include offshore/onshore txs if we cant calculate a valid block cap.
          if (!have_valid_pr) {
            continue;
          }

          if (tx_type == tt::OFFSHORE) {
            conversion_this_tx_xhv += tx.amount_burnt;
          }
          if (tx_type == tt::ONSHORE) {
            conversion_this_tx_xhv += tx.amount_minted;
          }

          if (total_conversion_xhv + conversion_this_tx_xhv > block_cap_xhv) {
            continue;
          }
        }

        // Validate that pricing record has not grown too old since it was first included in the pool
        if (!tx_pr_height_valid(m_blockchain.get_current_blockchain_height(), tx.pricing_record_height, sorted_it->second)) {
          LOG_PRINT_L2("error : offshore/xAsset transaction references a pricing record that is too old (height " << tx.pricing_record_height << ")");
          continue;
        }

        // check for verRctSemantics2
        if (hf_version >= HF_VERSION_HAVEN2) {

          // get pricing record
          block bl;
          if (!m_blockchain.get_block_by_hash(m_blockchain.get_block_id_by_height(tx.pricing_record_height), bl)) {
            LOG_PRINT_L2("error: failed to get block containing pricing record");
            continue;
          }

          // Get the slippage
          uint64_t slippage = 0;
          if (hf_version >= HF_VERSION_SLIPPAGE && source != dest) {
            if (!get_slippage(tx_type, source, dest, tx.amount_burnt, slippage, bl.pricing_record, supply_amounts, hf_version)) {
              LOG_PRINT_L2("error: failed to obtain slippage requirements for tx " << tx.hash);
              continue;
            }
          }
          
          // Get the collateral requirement for the tx
          uint64_t collateral = 0;
          if (hf_version >= HF_VERSION_USE_COLLATERAL && (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE)) {
            if (!get_collateral_requirements(tx_type, tx.amount_burnt, collateral, bl.pricing_record, supply_amounts, hf_version)) {
              LOG_PRINT_L2("error: failed to get collateral requirements");
              continue;
            }
          }

          // NEAC: Get conversion rate so we can avoid doing an invert() on a number with excessive precision
          uint64_t conversion_rate = COIN;
          if (!cryptonote::get_conversion_rate(bl.pricing_record, source, dest, conversion_rate, hf_version)) {
            LOG_PRINT_L2("error: failed to get conversion rate - aborting");
            continue;
          }
          
          // Get the fee conversion rate used
          uint64_t fee_conversion_rate = COIN;
          if (!cryptonote::get_conversion_rate(bl.pricing_record, source, "XHV", fee_conversion_rate, hf_version)) {
            LOG_PRINT_L2("error: unable to obtain fee conversion rate.");
            continue;
          }
          
          // Get the TX fee conversion rate used
          uint64_t tx_fee_conversion_rate = COIN;
          if (!cryptonote::get_conversion_rate(bl.pricing_record, "XHV", source, tx_fee_conversion_rate, hf_version)) {
            LOG_PRINT_L2("error: unable to obtain TX fee conversion rate.");
            continue;
          }
          
          // make sure proof-of-value still holds
          if (!rct::verRctSemanticsSimple2(tx.rct_signatures, bl.pricing_record, conversion_rate, fee_conversion_rate, tx_fee_conversion_rate, tx_type, source, dest, tx.amount_burnt, tx.amount_minted, tx.vout, tx.vin, hf_version, collateral, slippage, tvc.m_tx_anon_pool))
          {
            LOG_PRINT_L2(" transaction proof-of-value is now invalid for tx " << sorted_it->second);
            continue;
          }
        }
      } else {
        // make sure proof-of-value still holds for transfers after HF_VERSION_BURN
        if (hf_version>HF_VERSION_BURN){
          uint64_t slippage = 0;
          uint64_t collateral = 0;
          uint64_t conversion_rate = COIN;
          uint64_t fee_conversion_rate = COIN;
          uint64_t tx_fee_conversion_rate = COIN;
          offshore::pricing_record pr_empty;
          if (!rct::verRctSemanticsSimple2(tx.rct_signatures, pr_empty, conversion_rate, fee_conversion_rate, tx_fee_conversion_rate, tx_type, source, dest, tx.amount_burnt, tx.amount_minted, tx.vout, tx.vin, hf_version, collateral, slippage, tvc.m_tx_anon_pool))
          {
            LOG_PRINT_L2(" transaction proof-of-value is now invalid for tx " << sorted_it->second);
            continue;
          }
        }
      }

      bl.tx_hashes.push_back(sorted_it->second);
      total_weight += meta.weight;
      total_fee_xhv += total_fee_this_tx_xhv;
      total_conversion_xhv += conversion_this_tx_xhv;
      fee_map[meta.fee_asset_type] += meta.fee;
      if (source != dest) {
        if (hf_version >= HF_VERSION_XASSET_FEES_V2 && source != "XHV" && dest != "XHV") {
          // xAsset converison
          xasset_fee_map[meta.fee_asset_type] += meta.offshore_fee;
        } else {
          // offshore/onshore
          offshore_fee_map[meta.fee_asset_type] += meta.offshore_fee;
        }
      }
      best_coinbase = coinbase;
      append_key_images(k_images, tx);
      LOG_PRINT_L2("  added, new block weight " << total_weight << "/" << max_total_weight << ", coinbase " << print_money(best_coinbase));
    }
    lock.commit();

    expected_reward = best_coinbase;
    // HERE BE DRAGONS!!!
    // NEAC: add in a function to iteratively output all currencies in a map as money - should live in cryptonote_tx_utils.cpp as a helper fn
    LOG_PRINT_L2("Block template filled with " << bl.tx_hashes.size() << " txes, weight "
        << total_weight << "/" << max_total_weight << ", coinbase " << print_money(best_coinbase)
        << " (including " << print_money(fee_map["XHV"]) << " in fees)");
    // LAND AHOY!!!
    return true;
  }
  //---------------------------------------------------------------------------------
  size_t tx_memory_pool::validate(uint8_t version)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    MINFO("Validating txpool contents for v" << (unsigned)version);

    LockedTXN lock(m_blockchain.get_db());

    struct tx_entry_t
    {
      crypto::hash txid;
      txpool_tx_meta_t meta;
    };

    // get all txids
    std::vector<tx_entry_t> txes;
    m_blockchain.for_all_txpool_txes([&txes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref*) {
      if (!meta.pruned) // skip pruned txes
        txes.push_back({txid, meta});
      return true;
    }, false, relay_category::all);

    // take them all out and add them back in, some might fail
    size_t added = 0;
    for (auto &e: txes)
    {
      try
      {
        size_t weight;
        uint64_t fee, offshore_fee;
        std::string fee_asset_type;
        cryptonote::transaction tx;
        cryptonote::blobdata blob;
        bool relayed, do_not_relay, double_spend_seen, pruned;
        if (!take_tx(e.txid, tx, blob, weight, fee, offshore_fee, fee_asset_type, relayed, do_not_relay, double_spend_seen, pruned))
          MERROR("Failed to get tx " << e.txid << " from txpool for re-validation");

        cryptonote::tx_verification_context tvc{};
        relay_method tx_relay = e.meta.get_relay_method();
        bool ok = false;
        if (version >= HF_VERSION_HAVEN2) {
          ok = add_tx2(tx, e.txid, blob, e.meta.weight, tvc, tx_relay, relayed, version);
        } else {
          ok = add_tx(tx, e.txid, blob, e.meta.weight, tvc, tx_relay, relayed, version);
        }
        if (!ok) {
          MINFO("Failed to re-validate tx " << e.txid << " for v" << (unsigned)version << ", dropped");
          continue;
        }
        m_blockchain.update_txpool_tx(e.txid, e.meta);
        ++added;
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to re-validate tx from pool");
        continue;
      }
    }

    lock.commit();

    const size_t n_removed = txes.size() - added;
    if (n_removed > 0)
      ++m_cookie;
    return n_removed;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::init(size_t max_txpool_weight, bool mine_stem_txes)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    m_txpool_max_weight = max_txpool_weight ? max_txpool_weight : DEFAULT_TXPOOL_MAX_WEIGHT;
    m_txs_by_fee_and_receive_time.clear();
    m_spent_key_images.clear();
    m_txpool_weight = 0;
    std::vector<crypto::hash> remove;

    // first add the not kept by block, then the kept by block,
    // to avoid rejection due to key image collision
    for (int pass = 0; pass < 2; ++pass)
    {
      const bool kept = pass == 1;
      bool r = m_blockchain.for_all_txpool_txes([this, &remove, kept](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata_ref *bd) {
        if (!!kept != !!meta.kept_by_block)
          return true;
        cryptonote::transaction_prefix tx;
        if (!parse_and_validate_tx_prefix_from_blob(*bd, tx))
        {
          MWARNING("Failed to parse tx from txpool, removing");
          remove.push_back(txid);
          return true;
        }
        if (!insert_key_images(tx, txid, meta.get_relay_method()))
        {
          MFATAL("Failed to insert key images from txpool tx");
          return false;
        }
        m_txs_by_fee_and_receive_time.emplace(std::pair<double, time_t>(meta.fee / (double)meta.weight, meta.receive_time), txid);
        m_txpool_weight += meta.weight;
        return true;
      }, true, relay_category::all);
      if (!r)
        return false;
    }
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const auto &txid: remove)
      {
        try
        {
          m_blockchain.remove_txpool_tx(txid);
        }
        catch (const std::exception &e)
        {
          MWARNING("Failed to remove corrupt transaction: " << txid);
          // ignore error
        }
      }
      lock.commit();
    }

    m_mine_stem_txes = mine_stem_txes;
    m_cookie = 0;

    // Ignore deserialization error
    return true;
  }

  //---------------------------------------------------------------------------------
  bool tx_memory_pool::deinit()
  {
    return true;
  }
}
