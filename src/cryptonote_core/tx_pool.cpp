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

        This value was calculated with k=10, ep=0.10, and hop = 175 ms. A
        testrun from a recent Intel laptop took ~80ms to
        receive+parse+proces+send transaction. At least 50ms will be added to
        the latency if crossing an ocean. So 175ms is the fudge factor for
        a single hop with 173s being the embargo timer. */
    constexpr const std::chrono::seconds dandelionpp_embargo_average{CRYPTONOTE_DANDELIONPP_EMBARGO_AVERAGE};

    //TODO: constants such as these should at least be in the header,
    //      but probably somewhere more accessible to the rest of the
    //      codebase.  As it stands, it is at best nontrivial to test
    //      whether or not changing these parameters (or adding new)
    //      will work correctly.
    time_t const MIN_RELAY_TIME = (60 * 5); // only start re-relaying transactions after that many seconds
    time_t const MAX_RELAY_TIME = (60 * 60 * 4); // at most that many seconds between resends
    float const ACCEPT_THRESHOLD = 1.0f;

    // a kind of increasing backoff within min/max bounds
    uint64_t get_relay_delay(time_t now, time_t received)
    {
      time_t d = (now - received + MIN_RELAY_TIME) / MIN_RELAY_TIME * MIN_RELAY_TIME;
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
      // from v5, limit a tx to 50% of the minimum block weight
      if (version >= 5)
        return get_min_block_weight(version) / 2 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
      else
        return get_min_block_weight(version) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    }
  }
  //---------------------------------------------------------------------------------
  //---------------------------------------------------------------------------------
  tx_memory_pool::tx_memory_pool(Blockchain& bchs): m_blockchain(bchs), m_cookie(0), m_txpool_max_weight(DEFAULT_TXPOOL_MAX_WEIGHT), m_txpool_weight(0), m_mine_stem_txes(false)
  {

  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::add_tx(transaction &tx, /*const crypto::hash& tx_prefix_hash,*/ const crypto::hash &id, const cryptonote::blobdata &blob, size_t tx_weight, tx_verification_context& tvc, relay_method tx_relay, bool relayed, uint8_t version)
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

    // fee per kilobyte, size rounded up.
    uint64_t fee = 0, fee_usd = 0, fee_xasset = 0, offshore_fee = 0, offshore_fee_usd = 0, offshore_fee_xasset = 0;

    if (tx.version == 1)
    {
      uint64_t inputs_amount = 0;
      if(!get_inputs_money_amount(tx, inputs_amount))
      {
        tvc.m_verifivation_failed = true;
        return false;
      }

      uint64_t outputs_amount = get_outs_money_amount(tx)["XHV"];
      if(outputs_amount > inputs_amount)
      {
        LOG_PRINT_L1("transaction use more money than it has: use " << print_money(outputs_amount) << ", have " << print_money(inputs_amount));
        tvc.m_verifivation_failed = true;
        tvc.m_overspend = true;
        return false;
      }
      else if(outputs_amount == inputs_amount)
      {
        LOG_PRINT_L1("transaction fee is zero: outputs_amount == inputs_amount, rejecting.");
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
      }

      fee = inputs_amount - outputs_amount;
    }
    else
    {
      fee = tx.rct_signatures.txnFee;
      fee_usd = tx.rct_signatures.txnFee_usd;
      fee_xasset = tx.rct_signatures.txnFee_xasset;
      offshore_fee = tx.rct_signatures.txnOffshoreFee;
      offshore_fee_usd = tx.rct_signatures.txnOffshoreFee_usd;
      offshore_fee_xasset = tx.rct_signatures.txnOffshoreFee_xasset;
    }

    // check the fee
    if (!kept_by_block) {
      if ((!fee || !m_blockchain.check_fee(tx_weight, fee)) && (!fee_usd || !m_blockchain.check_fee(tx_weight, fee_usd)) && (!fee_xasset || !m_blockchain.check_fee(tx_weight, fee_xasset)))
      {
        tvc.m_verifivation_failed = true;
        tvc.m_fee_too_low = true;
        return false;
      }
    }

    //validate the offshore data
    bool bOffshoreTx = false;
    tx_extra_offshore offshore_data;
    if (tx.extra.size()) {
      bOffshoreTx = get_offshore_from_tx_extra(tx.extra, offshore_data);
    }
    if (bOffshoreTx) {
      if (version >= HF_VERSION_XASSET_FULL) {
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
      } else if (version >= HF_VERSION_OFFSHORE_FULL) {
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
        if (version >= HF_VERSION_XASSET_FULL) {
          // old offshore data format suplied to tx extra
          LOG_PRINT_L1("Empty tx_offshore_data." << id);
          tvc.m_verifivation_failed = true;
          return false;
        } else if (version >= HF_VERSION_OFFSHORE_FULL) {
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
    bool offshore = false;
    bool onshore = false;
    bool offshore_transfer = false;
    bool xasset_transfer = false;
    bool xasset_to_xusd = false;
    bool xusd_to_xasset = false;
    std::string source;
    std::string dest;
    offshore::pricing_record pr;
    
    if (!get_tx_asset_types(tx, source, dest)) {
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

    // Get the TX type flags
    if (!get_tx_type(source, dest, offshore, onshore, offshore_transfer, xusd_to_xasset, xasset_to_xusd, xasset_transfer)) {
      LOG_ERROR("At least 1 input or 1 output of the tx was invalid." << tx.hash);
      tvc.m_verifivation_failed = true;
      return false;
    }

    if (offshore || onshore || xusd_to_xasset || xasset_to_xusd) {

      // Validate that pricing record is not too old
      uint64_t current_height = m_blockchain.get_current_blockchain_height();
      if ((current_height - PRICING_RECORD_VALID_BLOCKS) > tx.pricing_record_height) {
	LOG_PRINT_L2("error : offshore/xAsset transaction references a pricing record that is too old (height " << tx.pricing_record_height << ")");
	tvc.m_verifivation_failed = true;
	return false;
      }
      
      // this check is here because of a soft fork that needed to happen due to invalid pr
      if (tx.pricing_record_height > 658500) {
        // NEAC: recover from the reorg during Oracle switch - 1 TX affected
        offshore::pricing_record pr;
        if (tx.pricing_record_height == 821428) {
          const std::string pr_821428 = "9b3f6f2f8f0000003d620e1202000000be71be2555120000b8627010000000000000000000000000ea0885b2270d00000000000000000000f797ff9be00b0000ddbdb005270a0000fc90cfe02b01060000000000000000000000000000000000d0a28224000e000000d643be960e0000002e8bb6a40e000000f8a817f80d00002f5d27d45cdbfbac3d0f6577103f68de30895967d7562fbd56c161ae90130f54301b1ea9d5fd062f37dac75c3d47178bc6f149d21da1ff0e8430065cb762b93a";
          pr.xAG = 614976143259;
          pr.xAU = 8892867133;
          pr.xAUD = 20156914758078;
          pr.xBTC = 275800760;
          pr.xCAD = 0;
          pr.xCHF = 14464149948650;
          pr.xCNY = 0;
          pr.xEUR = 13059317798903;
          pr.xGBP = 11162715471325;
          pr.xJPY = 1690137827184892;
          pr.xNOK = 0;
          pr.xNZD = 0;
          pr.xUSD = 15393775330000;
          pr.unused1 = 16040600000000;
          pr.unused2 = 16100600000000;
          pr.unused3 = 15359200000000;
          std::string sig = "2f5d27d45cdbfbac3d0f6577103f68de30895967d7562fbd56c161ae90130f54301b1ea9d5fd062f37dac75c3d47178bc6f149d21da1ff0e8430065cb762b93a";
          int j=0;
          for (unsigned int i = 0; i < sig.size(); i += 2) {
            std::string byteString = sig.substr(i, 2);
            pr.signature[j++] = (char) strtol(byteString.c_str(), NULL, 16);
          }
          
          if (!pr.verifySignature()) {
            LOG_ERROR("Failed to set correct PR for block: " << tx.pricing_record_height);
            return false;
          }
        } else {
          // Get the pricing record that was used for conversion
          block bl;
          bool r = m_blockchain.get_block_by_hash(m_blockchain.get_block_id_by_height(tx.pricing_record_height), bl);
          if (!r) {
            LOG_ERROR("error: failed to get block containing pricing record");
            tvc.m_verifivation_failed = true;
            return false;
          }

          pr = bl.pricing_record;
        }
	
        // Check the amount burnt and minted
        if (!rct::checkBurntAndMinted(tx.rct_signatures, tx.amount_burnt, tx.amount_minted, pr, source, dest)) {
          LOG_PRINT_L1("amount burnt / minted is incorrect: burnt = " << tx.amount_burnt << ", minted = " << tx.amount_minted);
          tvc.m_verifivation_failed = true;
          return false;
        }

        // Verify the offshore conversion fee is present and correct here
        uint64_t unlock_time = tx.unlock_time - tx.pricing_record_height;
        if (offshore || onshore) {
          if (unlock_time < 180) {
            LOG_PRINT_L1("unlock_time is too short: " << unlock_time << " blocks - rejecting (minimum permitted is 180 blocks)");
            tvc.m_verifivation_failed = true;
            return false;
          }
        }
        uint64_t priority = (unlock_time >= 5040) ? 1 : (unlock_time >= 1440) ? 2 : (unlock_time >= 720) ? 3 : 4;
        uint64_t conversion_fee_check = 0;
        if (offshore || onshore) {
          conversion_fee_check = (priority == 1) ? tx.amount_burnt / 500 : (priority == 2) ? tx.amount_burnt / 20 : (priority == 3) ? tx.amount_burnt / 10 : tx.amount_burnt / 5;
        } else if (xusd_to_xasset || xasset_to_xusd) {
          // Flat 0.3% conversion fee for xAsset TXs
          conversion_fee_check = (tx.amount_burnt * 3) / 1000;
        }
        if ((offshore && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee)) ||
            ((onshore || xusd_to_xasset) && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee_usd)) ||
	    (xasset_to_xusd && (conversion_fee_check != tx.rct_signatures.txnOffshoreFee_xasset))) 
        {
          LOG_PRINT_L1("conversion fee is incorrect - rejecting");
          tvc.m_verifivation_failed = true;
          tvc.m_fee_too_low = true;
          return false;
        }
      }
    }
    
    size_t tx_weight_limit = get_transaction_weight_limit(version);
    if ((!kept_by_block || version >= HF_VERSION_PER_BYTE_FEE) && tx_weight > tx_weight_limit)
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
    size_t blob_size = 0;
    cryptonote::blobdata bl;
    t_serializable_object_to_blob(tx, bl);
    if (bl.size() == 0 || !get_transaction_hash(tx, h))
      return false;
    return add_tx(tx, h, bl, get_transaction_weight(tx, bl.size()), tvc, tx_relay, relayed, version);
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
          MERROR("Failed to find tx_meta in txpool");
          return;
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
        m_txpool_weight -= meta.weight;
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
    
    if (tx.vin[0].type() == typeid(txin_offshore)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_offshore, txin, false);
        std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
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
    }
    else if (tx.vin[0].type() == typeid(txin_onshore)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_onshore, txin, false);
        std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
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
    }
    else if (tx.vin[0].type() == typeid(txin_xasset)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_xasset, txin, false);
        std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
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
    }
    else if (tx.vin[0].type() == typeid(txin_to_key)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, txin, false);
        std::unordered_set<crypto::hash>& kei_image_set = m_spent_key_images[txin.k_image];
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
    if (tx.vin[0].type() == typeid(txin_onshore)) {
      for(const txin_v& vi: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_onshore, txin, false);
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
    }
    else if (tx.vin[0].type() == typeid(txin_offshore)) {
      for(const txin_v& vi: tx.vin)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_offshore, txin, false);
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
    }
    else if (tx.vin[0].type() == typeid(txin_xasset)) {
      for(const txin_v& vi: tx.vin)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_xasset, txin, false);
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
    }
    else {
      for(const txin_v& vi: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(vi, const txin_to_key, txin, false);
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

    m_blockchain.for_all_txpool_txes([this, &hashes, &txes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata*) {
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
    m_blockchain.for_all_txpool_txes([this, &remove](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata*) {
      uint64_t tx_age = time(nullptr) - meta.receive_time;

      if((tx_age > CRYPTONOTE_MEMPOOL_TX_LIVETIME && !meta.kept_by_block) ||
         (tx_age > CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME && meta.kept_by_block) )
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
            m_txpool_weight -= entry.second;
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
  bool tx_memory_pool::get_relayable_transactions(std::vector<std::tuple<crypto::hash, cryptonote::blobdata, relay_method>> &txs) const
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    const uint64_t now = time(NULL);
    txs.reserve(m_blockchain.get_txpool_tx_count());
    m_blockchain.for_all_txpool_txes([this, now, &txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *){
      // 0 fee transactions are never relayed
				       if(!meta.pruned && (meta.fee > 0))
      {
        if (!meta.dandelionpp_stem && now - meta.last_relayed_time <= get_relay_delay(now, meta.receive_time))
          return true;
        if (meta.dandelionpp_stem && meta.last_relayed_time < now) // for dandelion++ stem, this value is the embargo timeout
          return true;

        // if the tx is older than half the max lifetime, we don't re-relay it, to avoid a problem
        // mentioned by smooth where nodes would flush txes at slightly different times, causing
        // flushed txes to be re-added when received from a node which was just about to flush it
        uint64_t max_age = meta.kept_by_block ? CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME : CRYPTONOTE_MEMPOOL_TX_LIVETIME;
        if (now - meta.receive_time <= max_age / 2)
        {
          try
          {
            txs.emplace_back(txid, m_blockchain.get_txpool_tx_blob(txid, relay_category::all), meta.get_relay_method());
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
    return true;
  }
  //---------------------------------------------------------------------------------
  void tx_memory_pool::set_relayed(const epee::span<const crypto::hash> hashes, const relay_method method)
  {
    crypto::random_poisson_seconds embargo_duration{dandelionpp_embargo_average};
    const auto now = std::chrono::system_clock::now();

    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);
    LockedTXN lock(m_blockchain.get_db());
    for (const auto& hash : hashes)
    {
      try
      {
        txpool_tx_meta_t meta;
        if (m_blockchain.get_txpool_tx_meta(hash, meta))
        {
          // txes can be received as "stem" or "fluff" in either order
          meta.upgrade_relay_method(method);
          meta.relayed = true;

          if (meta.dandelionpp_stem)
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now + embargo_duration());
          else
            meta.last_relayed_time = std::chrono::system_clock::to_time_t(now);

          m_blockchain.update_txpool_tx(hash, meta);
        }
      }
      catch (const std::exception &e)
      {
        MERROR("Failed to update txpool transaction metadata: " << e.what());
        // continue
      }
    }
    lock.commit();
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
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
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
    m_blockchain.for_all_txpool_txes([&txs](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
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
    m_blockchain.for_all_txpool_txes([&backlog, now](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      backlog.push_back({meta.weight, meta.fee, meta.receive_time - now});
      return true;
    }, false, category);
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
    m_blockchain.for_all_txpool_txes([&stats, &weights, now, &agebytes](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
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
    m_blockchain.for_all_txpool_txes([&tx_infos, key_image_infos, include_sensitive_data](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
      tx_info txi;
      txi.id_hash = epee::string_tools::pod_to_hex(txid);
      txi.tx_blob = *bd;
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

    txpool_tx_meta_t meta;
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
    m_blockchain.for_all_txpool_txes([&tx_infos, key_image_infos](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd){
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
    if (tx.vin[0].type() == typeid(txin_to_key)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_to_key, tokey_in, true);//should never fail
        if(have_tx_keyimg_as_spent(tokey_in.k_image, txid))
          return true;
      }
    }
    else if (tx.vin[0].type() == typeid(txin_offshore)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_offshore, tokey_in, true);//should never fail
        if(have_tx_keyimg_as_spent(tokey_in.k_image, txid))
          return true;
      }
    }
    else if (tx.vin[0].type() == typeid(txin_onshore)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_onshore, tokey_in, true);//should never fail
        if(have_tx_keyimg_as_spent(tokey_in.k_image, txid))
          return true;
      }
    }
    else if (tx.vin[0].type() == typeid(txin_xasset)) {
      for(const auto& in: tx.vin)
      {
        CHECKED_GET_SPECIFIC_VARIANT(in, const txin_xasset, tokey_in, true);//should never fail
        if(have_tx_keyimg_as_spent(tokey_in.k_image, txid))
          return true;
      }
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
    bool ret = m_blockchain.check_tx_inputs(get_tx(), max_used_block_height, max_used_block_id, tvc, kept_by_block);
    if (!kept_by_block)
      m_input_cache.insert(std::make_pair(txid, std::make_tuple(ret, tvc, max_used_block_height, max_used_block_id)));
    return ret;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::is_transaction_ready_to_go(txpool_tx_meta_t& txd, const crypto::hash &txid, const cryptonote::blobdata &txblob, transaction &tx) const
  {
    struct transction_parser
    {
      transction_parser(const cryptonote::blobdata &txblob, const crypto::hash &txid, transaction &tx): txblob(txblob), txid(txid), tx(tx), parsed(false) {}
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
      const cryptonote::blobdata &txblob;
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
  bool tx_memory_pool::have_key_images(const std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    if (tx.vin[0].type() == typeid(txin_to_key)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, false);
	  if(k_images.count(itk.k_image))
	    return true;
	}
    }
    else if (tx.vin[0].type() == typeid(txin_offshore)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_offshore, itk, false);
	  if(k_images.count(itk.k_image))
	    return true;
	}
    }
    else if (tx.vin[0].type() == typeid(txin_onshore)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_onshore, itk, false);
	  if(k_images.count(itk.k_image))
	    return true;
	}
    }
    else if (tx.vin[0].type() == typeid(txin_xasset)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_xasset, itk, false);
	  if(k_images.count(itk.k_image))
	    return true;
	}
    }
    return false;
  }
  //---------------------------------------------------------------------------------
  bool tx_memory_pool::append_key_images(std::unordered_set<crypto::key_image>& k_images, const transaction_prefix& tx)
  {
    if (tx.vin[0].type() == typeid(txin_to_key)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, false);
	  auto i_res = k_images.insert(itk.k_image);
	  CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
	}
    }
    else if (tx.vin[0].type() == typeid(txin_offshore)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_offshore, itk, false);
	  auto i_res = k_images.insert(itk.k_image);
	  CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
	}
    }
    else if (tx.vin[0].type() == typeid(txin_onshore)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_onshore, itk, false);
	  auto i_res = k_images.insert(itk.k_image);
	  CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
	}
    }
    else if (tx.vin[0].type() == typeid(txin_xasset)) {
      for(size_t i = 0; i!= tx.vin.size(); i++)
	{
	  CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_xasset, itk, false);
	  auto i_res = k_images.insert(itk.k_image);
	  CHECK_AND_ASSERT_MES(i_res.second, false, "internal error: key images pool cache - inserted duplicate image in set: " << itk.k_image);
	}
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
      crypto::key_image itk_key_image;
      if (tx.vin[i].type() == typeid(txin_to_key)) {
	CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_to_key, itk, void());
        itk_key_image = itk.k_image;
      } else if (tx.vin[i].type() == typeid(txin_onshore)) {
	CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_onshore, itk, void());
        itk_key_image = itk.k_image;
      } else if (tx.vin[i].type() == typeid(txin_xasset)) {
	CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_xasset, itk, void());
        itk_key_image = itk.k_image;
      } else {
	CHECKED_GET_SPECIFIC_VARIANT(tx.vin[i], const txin_offshore, itk, void());
        itk_key_image = itk.k_image;
      }
      const key_images_container::const_iterator it = m_spent_key_images.find(itk_key_image);
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
            MDEBUG("Marking " << txid << " as double spending " << itk_key_image);
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
    m_blockchain.for_all_txpool_txes([&ss, short_format](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *txblob) {
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
  bool tx_memory_pool::fill_block_template(block &bl, size_t median_weight, uint64_t already_generated_coins, size_t &total_weight, std::map<std::string, uint64_t> &fee_map, std::map<std::string, uint64_t> &offshore_fee_map, uint64_t &expected_reward, uint8_t version)
  {
    CRITICAL_REGION_LOCAL(m_transactions_lock);
    CRITICAL_REGION_LOCAL1(m_blockchain);

    uint64_t best_coinbase = 0, coinbase = 0;
    total_weight = 0;
    
    //baseline empty block
    if (!get_block_reward(median_weight, total_weight, already_generated_coins, best_coinbase, version))
    {
      MERROR("Failed to get block reward for empty block");
      return false;
    }

    size_t max_total_weight_pre_v5 = (130 * median_weight) / 100 - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    size_t max_total_weight_v5 = 2 * median_weight - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
    size_t max_total_weight = version >= 5 ? max_total_weight_v5 : max_total_weight_pre_v5;
    std::unordered_set<crypto::key_image> k_images;

    LOG_PRINT_L2("Filling block template, median weight " << median_weight << ", " << m_txs_by_fee_and_receive_time.size() << " txes in the pool");

    LockedTXN lock(m_blockchain.get_db());

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
      if (version >= 5)
      {
        // If we're getting lower coinbase tx,
        // stop including more tx
        uint64_t block_reward;
        if(!get_block_reward(median_weight, total_weight + meta.weight, already_generated_coins, block_reward, version))
        {
          LOG_PRINT_L2("  would exceed maximum block weight");
          continue;
        }
	if (strcmp(meta.fee_asset_type, "XHV") == 0) {
	  coinbase = block_reward + fee_map["XHV"] + meta.fee;
	} else {
	  coinbase = block_reward + fee_map["XHV"];
	}
	/*
        if (coinbase < template_accept_threshold(best_coinbase))
        */
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

      bl.tx_hashes.push_back(sorted_it->second);
      total_weight += meta.weight;
      fee_map[meta.fee_asset_type] += meta.fee;
      offshore_fee_map[meta.fee_asset_type] += meta.offshore_fee;
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
    size_t tx_weight_limit = get_transaction_weight_limit(version);
    std::unordered_set<crypto::hash> remove;

    m_txpool_weight = 0;
    m_blockchain.for_all_txpool_txes([this, &remove, tx_weight_limit](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata*) {
      m_txpool_weight += meta.weight;
      if (meta.weight > tx_weight_limit) {
        LOG_PRINT_L1("Transaction " << txid << " is too big (" << meta.weight << " bytes), removing it from pool");
        remove.insert(txid);
      }
      else if (m_blockchain.have_tx(txid)) {
        LOG_PRINT_L1("Transaction " << txid << " is in the blockchain, removing it from pool");
        remove.insert(txid);
      }
      return true;
    }, false, relay_category::all);

    size_t n_removed = 0;
    if (!remove.empty())
    {
      LockedTXN lock(m_blockchain.get_db());
      for (const crypto::hash &txid: remove)
      {
        try
        {
          cryptonote::blobdata txblob = m_blockchain.get_txpool_tx_blob(txid, relay_category::all);
          cryptonote::transaction tx;
          if (!parse_and_validate_tx_from_blob(txblob, tx)) // remove pruned ones on startup, they're meant to be temporary
          {
            MERROR("Failed to parse tx from txpool");
            continue;
          }
          // remove tx from db first
          m_blockchain.remove_txpool_tx(txid);
          m_txpool_weight -= get_transaction_weight(tx, txblob.size());
          remove_transaction_keyimages(tx, txid);
          auto sorted_it = find_tx_in_sorted_container(txid);
          if (sorted_it == m_txs_by_fee_and_receive_time.end())
          {
            LOG_PRINT_L1("Removing tx " << txid << " from tx pool, but it was not found in the sorted txs container!");
          }
          else
          {
            m_txs_by_fee_and_receive_time.erase(sorted_it);
          }
          ++n_removed;
        }
        catch (const std::exception &e)
        {
          MERROR("Failed to remove invalid tx from pool");
          // continue
        }
      }
      lock.commit();
    }
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
      bool r = m_blockchain.for_all_txpool_txes([this, &remove, kept](const crypto::hash &txid, const txpool_tx_meta_t &meta, const cryptonote::blobdata *bd) {
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
