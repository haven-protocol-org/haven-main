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

#pragma once
#include "cryptonote_basic/cryptonote_format_utils.h"
#include <boost/serialization/vector.hpp>
#include <boost/serialization/utility.hpp>
#include "ringct/rctOps.h"

namespace cryptonote
{
  //---------------------------------------------------------------
  bool construct_miner_tx(size_t height, size_t median_weight, uint64_t already_generated_coins, size_t current_block_weight, std::map<std::string, uint64_t> fee_map,  std::map<std::string, uint64_t> offshore_fee_map, const account_public_address &miner_address, transaction& tx, const blobdata& extra_nonce = blobdata(), size_t max_outs = 999, uint8_t hard_fork_version = 1, cryptonote::network_type nettype = MAINNET);

  keypair get_deterministic_keypair_from_height(uint64_t height);

  uint64_t get_governance_reward(uint64_t height, uint64_t base_reward);

  bool get_deterministic_output_key(const account_public_address& address, const keypair& tx_key, size_t output_index, crypto::public_key& output_key);

  bool validate_governance_reward_key(uint64_t height, const std::string& governance_wallet_address_str, size_t output_index, const crypto::public_key& output_key, cryptonote::network_type nettype = MAINNET);
  struct tx_source_entry
  {
    typedef std::pair<uint64_t, rct::ctkey> output_entry;

    std::vector<output_entry> outputs;  //index + key + optional ringct commitment
    size_t real_output;                 //index in outputs vector of real output_entry
    crypto::public_key real_out_tx_key; //incoming real tx public key
    std::vector<crypto::public_key> real_out_additional_tx_keys; //incoming real tx additional public keys
    size_t real_output_in_tx_index;     //index in transaction outputs vector
    uint64_t amount;                    //money
    bool rct;                           //true if the output is rct
    rct::key mask;                      //ringct amount mask
    rct::multisig_kLRki multisig_kLRki; //multisig info
    uint64_t height;
    offshore::pricing_record pr;
    bool first_generation_input;
    std::string asset_type;
    
    void push_output(uint64_t idx, const crypto::public_key &k, uint64_t amount) { outputs.push_back(std::make_pair(idx, rct::ctkey({rct::pk2rct(k), rct::zeroCommit(amount)}))); }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(outputs)
      FIELD(real_output)
      FIELD(real_out_tx_key)
      FIELD(real_out_additional_tx_keys)
      FIELD(real_output_in_tx_index)
      FIELD(amount)
      FIELD(rct)
      FIELD(mask)
      FIELD(multisig_kLRki)

      if (real_output >= outputs.size())
        return false;

      FIELD(height)
      FIELD(pr)
      FIELD(asset_type)
      
    END_SERIALIZE()
  };

  struct tx_destination_entry
  {
    std::string original;
    uint64_t amount;                    //money
    uint64_t amount_usd;                //money
    uint64_t amount_xasset;             //money
    std::string asset_type;
    account_public_address addr;        //destination address
    bool is_subaddress;
    bool is_integrated;

    tx_destination_entry() : amount(0), amount_usd(0), amount_xasset(0), addr(AUTO_VAL_INIT(addr)), is_subaddress(false), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(uint64_t a, const account_public_address &ad, bool is_subaddress) : amount(a), amount_usd(0), amount_xasset(0), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(uint64_t a, uint64_t au, const account_public_address &ad, bool is_subaddress) : amount(a), amount_usd(au), amount_xasset(0), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(uint64_t a, uint64_t au, uint64_t ax, const account_public_address &ad, bool is_subaddress) : amount(a), amount_usd(au), amount_xasset(ax), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(uint64_t a, uint64_t au, uint64_t ax, const account_public_address &ad, bool is_subaddress, std::string currency) : amount(a), amount_usd(au), amount_xasset(ax), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type(currency) { }
    tx_destination_entry(const std::string &o, uint64_t a, const account_public_address &ad, bool is_subaddress) : original(o), amount(a), amount_usd(0), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(const std::string &o, uint64_t a, uint64_t au, const account_public_address &ad, bool is_subaddress) : original(o), amount(a), amount_usd(au), amount_xasset(0), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(const std::string &o, uint64_t a, uint64_t au, uint64_t ax, const account_public_address &ad, bool is_subaddress) : original(o), amount(a), amount_usd(au), amount_xasset(ax), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type("XHV") { }
    tx_destination_entry(const std::string &o, uint64_t a, uint64_t au, uint64_t ax, const account_public_address &ad, bool is_subaddress, std::string currency) : original(o), amount(a), amount_usd(au), amount_xasset(ax), addr(ad), is_subaddress(is_subaddress), is_integrated(false), asset_type(currency) { }
 
    std::string address(network_type nettype, const crypto::hash &payment_id) const
    {
      if (!original.empty())
      {
        return original;
      }

      if (is_integrated)
      {
        return get_account_integrated_address_as_str(nettype, addr, reinterpret_cast<const crypto::hash8 &>(payment_id));
      }

      return get_account_address_as_str(nettype, is_subaddress, addr);
    }

    BEGIN_SERIALIZE_OBJECT()
      FIELD(original)
      VARINT_FIELD(amount)
      VARINT_FIELD(amount_usd)
      VARINT_FIELD(amount_xasset)
      FIELD(asset_type)
      FIELD(addr)
      FIELD(is_subaddress)
      FIELD(is_integrated)
    END_SERIALIZE()
  };

  //---------------------------------------------------------------
  crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const boost::optional<cryptonote::account_public_address>& change_addr);
  bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry> &sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time);
  bool construct_tx_with_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, uint64_t current_height, offshore::pricing_record pr, uint32_t fees_version, bool use_offshore_tx_version = false, bool rct = false, const rct::RCTConfig &rct_config = { rct::RangeProofBorromean, 0 }, rct::multisig_out *msout = NULL, bool shuffle_outs = true);
  bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, const std::vector<uint8_t> &extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, uint64_t current_height, offshore::pricing_record pr, uint32_t fees_version, bool use_offshore_tx_version = false, bool rct = false, const rct::RCTConfig &rct_config = { rct::RangeProofBorromean, 0 }, rct::multisig_out *msout = NULL);
  bool generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key) ;

  bool generate_output_ephemeral_keys(const size_t tx_version, const cryptonote::account_keys &sender_account_keys, const crypto::public_key &txkey_pub,  const crypto::secret_key &tx_key,
                                      const cryptonote::tx_destination_entry &dst_entr, const boost::optional<cryptonote::account_public_address> &change_addr, const size_t output_index,
                                      const bool &need_additional_txkeys, const std::vector<crypto::secret_key> &additional_tx_keys,
                                      std::vector<crypto::public_key> &additional_tx_public_keys,
                                      std::vector<rct::key> &amount_keys,
                                      crypto::public_key &out_eph_public_key) ;

  bool generate_genesis_block(
      block& bl
    , std::string const & genesis_tx
    , uint32_t nonce
    , cryptonote::network_type nettype
    );

  class Blockchain;
  bool get_block_longhash(const Blockchain *pb, const block& b, crypto::hash& res, const uint64_t height, const int miners);
  void get_altblock_longhash(const block& b, crypto::hash& res, const uint64_t main_height, const uint64_t height,
    const uint64_t seed_height, const crypto::hash& seed_hash);
  crypto::hash get_block_longhash(const Blockchain *pb, const block& b, const uint64_t height, const int miners);
  void get_block_longhash_reorg(const uint64_t split_height);

  bool get_offshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height);
  bool get_onshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height);
  bool get_offshore_to_offshore_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height);
  bool get_xasset_to_xusd_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height);
  bool get_xusd_to_xasset_fee(const std::vector<cryptonote::tx_destination_entry> dsts, const uint32_t unlock_time, const offshore::pricing_record &pr, const uint32_t fees_version, uint64_t &fee_estimate, const std::vector<cryptonote::tx_source_entry> sources, const uint64_t height);
  bool get_tx_asset_types(const transaction& tx, std::string& source, std::string& destination);
  bool get_tx_type(const std::string& source, const std::string& destination, bool& offshore, bool& onshore, bool& offshore_transfer, bool& xusd_to_xasset, bool& xasset_to_xusd, bool& xasset_transfer);
 
}

BOOST_CLASS_VERSION(cryptonote::tx_source_entry, 5)
BOOST_CLASS_VERSION(cryptonote::tx_destination_entry, 4)

namespace boost
{
  namespace serialization
  {
    template <class Archive>
    inline void serialize(Archive &a, cryptonote::tx_source_entry &x, const boost::serialization::version_type ver)
    {
      a & x.outputs;
      a & x.real_output;
      a & x.real_out_tx_key;
      a & x.real_output_in_tx_index;
      a & x.amount;
      a & x.rct;
      a & x.mask;
      if (ver < 1)
        return;
      a & x.multisig_kLRki;
      a & x.real_out_additional_tx_keys;
      if (ver < 2) {
	return;
      }
      if (ver < 3) {
	return;
      }
      a & x.height;
      a & x.pr;
      if (ver < 4) {
	return;
      }
      a & x.first_generation_input;
      if (ver < 5) {
	return;
      }
      a & x.asset_type;
    }

    template <class Archive>
    inline void serialize(Archive& a, cryptonote::tx_destination_entry& x, const boost::serialization::version_type ver)
    {
      a & x.amount;
      a & x.addr;
      if (ver < 1)
        return;
      a & x.is_subaddress;
      if (ver < 2)
      {
        x.is_integrated = false;
        return;
      }
      a & x.original;
      a & x.is_integrated;
      if (ver < 3)
	return;
      a & x.amount_usd;
      if (ver < 4) {
	return;
      }
      a & x.amount_xasset;
      a & x.asset_type;
    }
  }
}
