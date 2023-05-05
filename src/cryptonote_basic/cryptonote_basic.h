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

#include <boost/variant.hpp>
#include <boost/functional/hash/hash.hpp>
#include <vector>
#include <cstring>  // memcmp
#include <sstream>
#include <atomic>
#include "serialization/variant.h"
#include "serialization/containers.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/crypto.h"
#include "serialization/keyvalue_serialization.h" // eepe named serialization
#include "serialization/pricing_record.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "ringct/rctTypes.h"
#include "device/device.hpp"
#include "cryptonote_basic/fwd.h"
#include "offshore/pricing_record.h"


#define SERIALIZE_OLD_TX_PREFIX(vin, vout, extra, offshore_data, output_unlock_times, collateral_indices, pricing_record_height, amount_burnt, amount_minted, version) \
{                                                                                                               \
  if (version < POU_TRANSACTION_VERSION)                                                                        \
  {                                                                                                             \
    VARINT_FIELD(unlock_time)                                                                                   \
  }                                                                                                             \
  if (!typename Archive<W>::is_saving()) {                                                                      \
    FIELD(vin)                                                                                                  \
    FIELD(vout)                                                                                                 \
    FIELD(extra)                                                                                                \
    if(version >= OFFSHORE_TRANSACTION_VERSION) {                                                               \
      VARINT_FIELD(pricing_record_height)                                                                       \
      if (version < 5)                                                                                          \
        FIELD(offshore_data)                                                                                    \
      if (version >= POU_TRANSACTION_VERSION) {                                                                 \
        FIELD(output_unlock_times)                                                                              \
        if (vout.size() != output_unlock_times.size()) {                                                        \
          return false;                                                                                         \
        }                                                                                                       \
      }                                                                                                         \
      VARINT_FIELD(amount_burnt)                                                                                \
      VARINT_FIELD(amount_minted)                                                                               \
      if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {                                          \
        FIELD(collateral_indices)                                                                               \
        if (collateral_indices.size() != 2) {                                                                   \
          return false;                                                                                         \
        }                                                                                                       \
        for (const auto vout_idx: collateral_indices) {                                                         \
          if (vout_idx >= vout.size())                                                                          \
            return false;                                                                                       \
        }                                                                                                       \
      }                                                                                                         \
    }                                                                                                           \
    std::vector<txin_v> vin_tmp(vin);                                                                           \
    vin.clear();                                                                                                \
    for (auto &vin_entry: vin_tmp) {                                                                            \
      if (vin_entry.type() == typeid(txin_gen)) {                                                               \
        vin.push_back(vin_entry);                                                                               \
        continue;                                                                                               \
      }                                                                                                         \
      txin_haven_key in;                                                                                        \
      if (vin_entry.type() == typeid(txin_to_key)) {                                                            \
        in.asset_type = "XHV";                                                                                  \
        in.amount = boost::get<txin_to_key>(vin_entry).amount;                                                  \
        in.key_offsets = boost::get<txin_to_key>(vin_entry).key_offsets;                                        \
        in.k_image = boost::get<txin_to_key>(vin_entry).k_image;                                                \
      } else if (vin_entry.type() == typeid(txin_offshore)) {                                                   \
        in.asset_type = "XUSD";                                                                                 \
        in.amount = boost::get<txin_offshore>(vin_entry).amount;                                                \
        in.key_offsets = boost::get<txin_offshore>(vin_entry).key_offsets;                                      \
        in.k_image = boost::get<txin_offshore>(vin_entry).k_image;                                              \
      } else if (vin_entry.type() == typeid(txin_onshore)) {                                                    \
        in.asset_type = "XUSD";                                                                                 \
        in.amount = boost::get<txin_onshore>(vin_entry).amount;                                                 \
        in.key_offsets = boost::get<txin_onshore>(vin_entry).key_offsets;                                       \
        in.k_image = boost::get<txin_onshore>(vin_entry).k_image;                                               \
      } else if (vin_entry.type() == typeid(txin_xasset)) {                                                     \
        in.amount = boost::get<txin_xasset>(vin_entry).amount;                                                  \
        in.key_offsets = boost::get<txin_xasset>(vin_entry).key_offsets;                                        \
        in.k_image = boost::get<txin_xasset>(vin_entry).k_image;                                                \
        in.asset_type = boost::get<txin_xasset>(vin_entry).asset_type;                                          \
      } else {                                                                                                  \
        return false;                                                                                           \
      }                                                                                                         \
      vin.push_back(in);                                                                                        \
    }                                                                                                           \
    std::vector<tx_out> vout_tmp(vout);                                                                         \
    vout.clear();                                                                                               \
    for (size_t i=0; i<vout_tmp.size(); i++) {                                                                  \
      txout_haven_key out;                                                                                      \
      if (vout_tmp[i].target.type() == typeid(txout_to_key)) {                                                  \
        out.asset_type = "XHV";                                                                                 \
        out.key = boost::get<txout_to_key>(vout_tmp[i].target).key;                                             \
      } else if (vout_tmp[i].target.type() == typeid(txout_offshore)) {                                         \
        out.asset_type = "XUSD";                                                                                \
        out.key = boost::get<txout_offshore>(vout_tmp[i].target).key;                                           \
      } else if (vout_tmp[i].target.type() == typeid(txout_xasset)) {                                           \
        out.asset_type = boost::get<txout_xasset>(vout_tmp[i].target).asset_type;                               \
        out.key = boost::get<txout_xasset>(vout_tmp[i].target).key;                                             \
      } else {                                                                                                  \
        return false;                                                                                           \
      }                                                                                                         \
      out.unlock_time = (version >= POU_TRANSACTION_VERSION) ? output_unlock_times[i] : unlock_time;            \
      out.is_collateral = false;                                                                                \
      out.is_collateral_change = false;                                                                         \
      if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {                                          \
        if (collateral_indices[0] != collateral_indices[1]) {                                                   \
          if (i == collateral_indices[0]) {                                                                     \
            out.is_collateral = true;                                                                           \
          } else if (i == collateral_indices[1]) {                                                              \
            out.is_collateral_change = true;                                                                    \
          }                                                                                                     \
        }                                                                                                       \
      }                                                                                                         \
      tx_out foo;                                                                                               \
      foo.amount = vout_tmp[i].amount;                                                                          \
      foo.target = out;                                                                                         \
      vout.push_back(foo);                                                                                      \
    }                                                                                                           \
    return true;                                                                                                \
  }                                                                                                             \
  std::vector<txin_v> vin_tmp;                                                                                  \
  vin_tmp.reserve(vin.size());                                                                                  \
  for (auto &vin_entry_v: vin) {                                                                                \
    if (vin_entry_v.type() == typeid(txin_gen)) {                                                               \
      vin_tmp.push_back(vin_entry_v);                                                                           \
      continue;                                                                                                 \
    }                                                                                                           \
    txin_haven_key vin_entry = boost::get<txin_haven_key>(vin_entry_v);                                         \
    if (vin_entry.asset_type == "XHV") {                                                                        \
      txin_to_key in;                                                                                           \
      in.amount = vin_entry.amount;                                                                             \
      in.key_offsets = vin_entry.key_offsets;                                                                   \
      in.k_image = vin_entry.k_image;                                                                           \
      vin_tmp.push_back(in);                                                                                    \
    } else if (vin_entry.asset_type == "XUSD") {                                                                \
      int xhv_outputs = std::count_if(vout.begin(), vout.end(), [](tx_out &foo_v) {                             \
        txout_haven_key out = boost::get<txout_haven_key>(foo_v.target);                                        \
        return out.asset_type == "XHV";                                                                         \
      });                                                                                                       \
      if (xhv_outputs) {                                                                                        \
        txin_onshore in;                                                                                        \
        in.amount = vin_entry.amount;                                                                           \
        in.key_offsets = vin_entry.key_offsets;                                                                 \
        in.k_image = vin_entry.k_image;                                                                         \
        vin_tmp.push_back(in);                                                                                  \
      } else {                                                                                                  \
        txin_offshore in;                                                                                       \
        in.amount = vin_entry.amount;                                                                           \
        in.key_offsets = vin_entry.key_offsets;                                                                 \
        in.k_image = vin_entry.k_image;                                                                         \
        vin_tmp.push_back(in);                                                                                  \
      }                                                                                                         \
    } else {                                                                                                    \
      txin_xasset in;                                                                                           \
      in.amount = vin_entry.amount;                                                                             \
      in.asset_type = vin_entry.asset_type;                                                                     \
      in.key_offsets = vin_entry.key_offsets;                                                                   \
      in.k_image = vin_entry.k_image;                                                                           \
      vin_tmp.push_back(in);                                                                                    \
    }                                                                                                           \
  }                                                                                                             \
  std::vector<tx_out> vout_tmp;                                                                                 \
  vout_tmp.reserve(vout.size());                                                                                \
  output_unlock_times.resize(vout.size());                                                                      \
  for (size_t i=0; i<vout.size(); i++) {                                                                        \
    txout_haven_key outhk = boost::get<txout_haven_key>(vout[i].target);                                        \
    tx_out foo;                                                                                                 \
    foo.amount = vout[i].amount;                                                                                \
    if (outhk.asset_type == "XHV") {                                                                            \
      txout_to_key out;                                                                                         \
      out.key = outhk.key;                                                                                      \
      foo.target = out;                                                                                         \
    } else if (outhk.asset_type == "XUSD") {                                                                    \
      txout_offshore out;                                                                                       \
      out.key = outhk.key;                                                                                      \
      foo.target = out;                                                                                         \
    } else {                                                                                                    \
      txout_xasset out;                                                                                         \
      out.asset_type = outhk.asset_type;                                                                        \
      out.key = outhk.key;                                                                                      \
      foo.target = out;                                                                                         \
    }                                                                                                           \
    output_unlock_times[i] = outhk.unlock_time;                                                                 \
    if (outhk.is_collateral) {                                                                                  \
    }                                                                                                           \
    vout_tmp.push_back(foo);                                                                                    \
  }                                                                                                             \
  FIELD_N("vin", vin_tmp)                                                                                       \
  FIELD_N("vout", vout_tmp)                                                                                     \
  FIELD(extra)                                                                                                  \
  if(version >= OFFSHORE_TRANSACTION_VERSION) {                                                                 \
    VARINT_FIELD(pricing_record_height)                                                                         \
    if (version < 5)                                                                                            \
      FIELD(offshore_data)                                                                                      \
    if (version >= POU_TRANSACTION_VERSION) {                                                                   \
      FIELD(output_unlock_times)                                                                                \
      if (vout.size() != output_unlock_times.size()) {                                                          \
        return false;                                                                                           \
      }                                                                                                         \
    }                                                                                                           \
    VARINT_FIELD(amount_burnt)                                                                                  \
    VARINT_FIELD(amount_minted)                                                                                 \
    if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {                                            \
      if (collateral_indices.size() != 2) {                                                                     \
        return false;                                                                                           \
      }                                                                                                         \
      FIELD(collateral_indices)                                                                                 \
      for (const auto vout_idx: collateral_indices) {                                                           \
        if (vout_idx >= vout.size())                                                                            \
          return false;                                                                                         \
      }                                                                                                         \
    }                                                                                                           \
  }                                                                                                             \
  return true;                                                                                                  \
}                                                                                                               \

namespace cryptonote
{
  typedef std::vector<crypto::signature> ring_signature;


  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  struct txout_offshore
  {
    txout_offshore() { }
    txout_offshore(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  struct txout_xasset
  {
    txout_xasset() { }
    txout_xasset(const crypto::public_key &_key, const std::string &_asset_type) : key(_key), asset_type(_asset_type) { }
    crypto::public_key key;
    std::string asset_type;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
    END_SERIALIZE()
  };

  // outputs <= HF_VERSION_VIEW_TAGS
  struct txout_haven_key
  {
    txout_haven_key() { }
    txout_haven_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const bool &_is_collateral, const bool &_is_collateral_change) : key(_key), asset_type(_asset_type), unlock_time(_unlock_time), is_collateral(_is_collateral), is_collateral_change(_is_collateral_change) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    bool is_collateral;
    bool is_collateral_change;
 
    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(is_collateral)
      FIELD(is_collateral_change)
    END_SERIALIZE()
   };

  // outputs >= HF_VERSION_VIEW_TAGS
  struct txout_haven_tagged_key
  {
    txout_haven_tagged_key() { }
    txout_haven_tagged_key(const crypto::public_key &_key, const std::string &_asset_type, const uint64_t &_unlock_time, const bool &_is_collateral, const bool &_is_collateral_change, const crypto::view_tag &_view_tag) : key(_key), asset_type(_asset_type), unlock_time(_unlock_time), is_collateral(_is_collateral), is_collateral_change(_is_collateral_change), view_tag(_view_tag) { }
    crypto::public_key key;
    std::string asset_type;
    uint64_t unlock_time;
    bool is_collateral;
    bool is_collateral_change;
    crypto::view_tag view_tag; // optimization to reduce scanning time
 
    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
      VARINT_FIELD(unlock_time)
      FIELD(is_collateral)
      FIELD(is_collateral_change)
      FIELD(view_tag)
    END_SERIALIZE()
   };

  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_offshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_onshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;
    
    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_xasset
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(asset_type)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };
  
  struct txin_haven_key
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(asset_type)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };
  
  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key, txin_offshore, txin_onshore, txin_xasset, txin_haven_key> txin_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_offshore, txout_xasset, txout_haven_key, txout_haven_tagged_key> txout_target_v;

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  class transaction_prefix
  {

  public:
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;
    // Block height to use PR from
    uint64_t pricing_record_height;
    // Circulating supply information
    std::vector<uint8_t> offshore_data;
    uint64_t amount_burnt;
    uint64_t amount_minted;
    std::vector<uint64_t> output_unlock_times;
    std::vector<uint32_t> collateral_indices;

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if(version == 0 || CURRENT_TRANSACTION_VERSION < version) return false;
    
      // Only transactions prior to HAVEN_TYPES_TRANSACTION_VERSION are permitted to be anything other than HAVEN_TYPES and need translation
      if (version < HAVEN_TYPES_TRANSACTION_VERSION) {

        if (version < POU_TRANSACTION_VERSION) {
          VARINT_FIELD(unlock_time)
        }
        if (!typename Archive<W>::is_saving()) {
          FIELD(vin)
          FIELD(vout)
          FIELD(extra)
          if(version >= OFFSHORE_TRANSACTION_VERSION) {
            VARINT_FIELD(pricing_record_height)
            if (version < 5)
              FIELD(offshore_data)
            if (version >= POU_TRANSACTION_VERSION) {
              FIELD(output_unlock_times)
              if (vout.size() != output_unlock_times.size()) {
                return false;
              }
            }
            VARINT_FIELD(amount_burnt)
            VARINT_FIELD(amount_minted)
            if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
              FIELD(collateral_indices)
              if (collateral_indices.size() != 2) {
                return false;
              }
              for (const auto vout_idx: collateral_indices) {
                if (vout_idx >= vout.size())
                  return false;
              }
            }
          }
          std::vector<txin_v> vin_tmp(vin);
          bool is_offshore_tx = (amount_burnt != 0);
          bool is_onshore_tx = false;
          vin.clear();
          for (auto &vin_entry: vin_tmp) {
            if (vin_entry.type() == typeid(txin_gen)) {
              vin.push_back(vin_entry);
              continue;
            }
            txin_haven_key in;
            if (vin_entry.type() == typeid(txin_to_key)) {
              in.asset_type = "XHV";
              in.amount = boost::get<txin_to_key>(vin_entry).amount;
              in.key_offsets = boost::get<txin_to_key>(vin_entry).key_offsets;
              in.k_image = boost::get<txin_to_key>(vin_entry).k_image;
            } else if (vin_entry.type() == typeid(txin_offshore)) {
              is_offshore_tx = false;
              is_onshore_tx = true;
              in.asset_type = "XUSD";
              in.amount = boost::get<txin_offshore>(vin_entry).amount;
              in.key_offsets = boost::get<txin_offshore>(vin_entry).key_offsets;
              in.k_image = boost::get<txin_offshore>(vin_entry).k_image;
            } else if (vin_entry.type() == typeid(txin_onshore)) {
              is_offshore_tx = false;
              is_onshore_tx = true;
              in.asset_type = "XUSD";
              in.amount = boost::get<txin_onshore>(vin_entry).amount;
              in.key_offsets = boost::get<txin_onshore>(vin_entry).key_offsets;
              in.k_image = boost::get<txin_onshore>(vin_entry).k_image;
            } else if (vin_entry.type() == typeid(txin_xasset)) {
              is_offshore_tx = false;
              in.amount = boost::get<txin_xasset>(vin_entry).amount;
              in.key_offsets = boost::get<txin_xasset>(vin_entry).key_offsets;
              in.k_image = boost::get<txin_xasset>(vin_entry).k_image;
              in.asset_type = boost::get<txin_xasset>(vin_entry).asset_type;
            } else {
              return false;
            }
            vin.push_back(in);
          }
          std::vector<tx_out> vout_tmp(vout);
          vout.clear();
          for (size_t i=0; i<vout_tmp.size(); i++) {
            txout_haven_key out;
            if (vout_tmp[i].target.type() == typeid(txout_to_key)) {
              out.asset_type = "XHV";
              out.key = boost::get<txout_to_key>(vout_tmp[i].target).key;
            } else if (vout_tmp[i].target.type() == typeid(txout_offshore)) {
              out.asset_type = "XUSD";
              out.key = boost::get<txout_offshore>(vout_tmp[i].target).key;
            } else if (vout_tmp[i].target.type() == typeid(txout_xasset)) {
              out.asset_type = boost::get<txout_xasset>(vout_tmp[i].target).asset_type;
              out.key = boost::get<txout_xasset>(vout_tmp[i].target).key;
            } else {
              return false;
            }
            out.unlock_time = (version >= POU_TRANSACTION_VERSION) ? output_unlock_times[i] : unlock_time;
            out.is_collateral = false;
            out.is_collateral_change = false;
            if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
              if (((is_onshore_tx) &&
                   (collateral_indices[0] == i)) ||
                  ((!is_onshore_tx) &&
                   (is_offshore_tx) &&
                   (collateral_indices[0] == i && collateral_indices[1] == 0))) {
                  out.is_collateral = true;
              }
              if (is_onshore_tx && collateral_indices[1] == i) {
                out.is_collateral_change = true;
              }
            }
            tx_out foo;
            foo.amount = vout_tmp[i].amount;
            foo.target = out;
            vout.push_back(foo);
          }
          return true;
        }
        bool is_offshore_tx = (amount_burnt != 0);
        bool is_onshore_tx = false;
        std::vector<txin_v> vin_tmp;
        vin_tmp.reserve(vin.size());
        for (auto &vin_entry_v: vin) {
          if (vin_entry_v.type() == typeid(txin_gen)) {
            vin_tmp.push_back(vin_entry_v);
            continue;
          }
          txin_haven_key vin_entry = boost::get<txin_haven_key>(vin_entry_v);
          if (vin_entry.asset_type == "XHV") {
            txin_to_key in;
            in.amount = vin_entry.amount;
            in.key_offsets = vin_entry.key_offsets;
            in.k_image = vin_entry.k_image;
            vin_tmp.push_back(in);
          } else if (vin_entry.asset_type == "XUSD") {
            is_offshore_tx = false;
            int xhv_outputs = std::count_if(vout.begin(), vout.end(), [](tx_out &foo_v) {
              if (foo_v.target.type() == typeid(txout_haven_key)) {
                txout_haven_key out = boost::get<txout_haven_key>(foo_v.target);
                return out.asset_type == "XHV";
              } else if (foo_v.target.type() == typeid(txout_haven_tagged_key)) {
                txout_haven_tagged_key out = boost::get<txout_haven_tagged_key>(foo_v.target);
                return out.asset_type == "XHV";
              } else {
                return false;
              }
            });
            if (xhv_outputs) {
              is_onshore_tx = true;
              txin_onshore in;
              in.amount = vin_entry.amount;
              in.key_offsets = vin_entry.key_offsets;
              in.k_image = vin_entry.k_image;
              vin_tmp.push_back(in);
            } else {
              txin_offshore in;
              in.amount = vin_entry.amount;
              in.key_offsets = vin_entry.key_offsets;
              in.k_image = vin_entry.k_image;
              vin_tmp.push_back(in);
            }
          } else {
            is_offshore_tx = false;
            txin_xasset in;
            in.amount = vin_entry.amount;
            in.asset_type = vin_entry.asset_type;
            in.key_offsets = vin_entry.key_offsets;
            in.k_image = vin_entry.k_image;
            vin_tmp.push_back(in);
          }
        }
        std::vector<tx_out> vout_tmp;
        vout_tmp.reserve(vout.size());
        output_unlock_times.resize(vout.size());
        std::vector<uint32_t> collateral_indices_temp;
        collateral_indices_temp.resize(2);
        for (size_t i=0; i<vout.size(); i++) {
          txout_haven_key outhk = boost::get<txout_haven_key>(vout[i].target);
          tx_out foo;
          foo.amount = vout[i].amount;
          if (outhk.asset_type == "XHV") {
            txout_to_key out;
            out.key = outhk.key;
            foo.target = out;
          } else if (outhk.asset_type == "XUSD") {
            txout_offshore out;
            out.key = outhk.key;
            foo.target = out;
          } else {
            txout_xasset out;
            out.asset_type = outhk.asset_type;
            out.key = outhk.key;
            foo.target = out;
          }
          output_unlock_times[i] = outhk.unlock_time;
          if (outhk.is_collateral) {
            collateral_indices_temp[0] = i;
          } else if (outhk.is_collateral_change) {
            collateral_indices_temp[1] = i;
          }
          vout_tmp.push_back(foo);
        }
        FIELD_N("vin", vin_tmp)
        FIELD_N("vout", vout_tmp)
        FIELD(extra)
        if(version >= OFFSHORE_TRANSACTION_VERSION) {
          VARINT_FIELD(pricing_record_height)
          if (version < 5)
            FIELD(offshore_data)
          if (version >= POU_TRANSACTION_VERSION) {
            FIELD(output_unlock_times)
            if (vout.size() != output_unlock_times.size()) {
              return false;
            }
          }
          VARINT_FIELD(amount_burnt)
          VARINT_FIELD(amount_minted)
          if (version >= COLLATERAL_TRANSACTION_VERSION && amount_burnt) {
            if (collateral_indices.size() != 2) {
              if ((is_offshore_tx || is_onshore_tx) && collateral_indices_temp.size() != 2) {
                return false;
              }
              if (is_offshore_tx || is_onshore_tx) {
                collateral_indices = collateral_indices_temp;
              } else {
                collateral_indices.clear();
                collateral_indices.push_back(0);
                collateral_indices.push_back(0);
              }
            }
            FIELD(collateral_indices)
            for (const auto vout_idx: collateral_indices) {
              if (vout_idx >= vout.size())
                return false;
            }
          }
        }
        return true;
        //SERIALIZE_OLD_TX_PREFIX(vin, vout, extra, offshore_data, output_unlock_times, collateral_indices, pricing_record_height, amount_burnt, amount_minted, version)
      }

      FIELD(vin)
      FIELD(vout)
      FIELD(extra)
      VARINT_FIELD(pricing_record_height)
      VARINT_FIELD(amount_burnt)
      VARINT_FIELD(amount_minted)
    END_SERIALIZE()

  public:
    transaction_prefix(){ set_null(); }
    void set_null()
    {
      version = 1;
      unlock_time = 0;
      vin.clear();
      vout.clear();
      extra.clear();
      pricing_record_height = 0;
      offshore_data.clear();
      amount_burnt = 0;
      amount_minted = 0;
      output_unlock_times.clear();
      collateral_indices.clear();
    }

    uint64_t get_unlock_time(size_t out_index) const
    {
      if (version >= HAVEN_TYPES_TRANSACTION_VERSION) {
        if (vout[out_index].target.type() == typeid(txout_haven_key)) {
          txout_haven_key out = boost::get<txout_haven_key>(vout[out_index].target);
          return out.unlock_time;
        } else if (vout[out_index].target.type() == typeid(txout_haven_tagged_key)) {
          txout_haven_tagged_key out = boost::get<txout_haven_tagged_key>(vout[out_index].target);
          return out.unlock_time;
        } else {
          LOG_ERROR("Failed to get output unlock time of a v8+ transaction output");
          return unlock_time;
        }
      }
      if (version >= POU_TRANSACTION_VERSION)
      {
        if (out_index >= output_unlock_times.size())
        {
          LOG_ERROR("Tried to get unlock time of a v6+ transaction with missing output unlock time");
          return unlock_time;
        }
        return output_unlock_times[out_index];
      }
      return unlock_time;
    }
  };

  class transaction: public transaction_prefix
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;
    mutable std::atomic<bool> prunable_hash_valid;
    mutable std::atomic<bool> blob_size_valid;

  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    // hash cash
    mutable crypto::hash hash;
    mutable crypto::hash prunable_hash;
    mutable size_t blob_size;

    bool pruned;

    std::atomic<unsigned int> unprunable_size;
    std::atomic<unsigned int> prefix_size;

    transaction();
    transaction(const transaction &t);
    transaction &operator=(const transaction &t);
    virtual ~transaction();
    void set_null();
    void invalidate_hashes();
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    bool is_prunable_hash_valid() const { return prunable_hash_valid.load(std::memory_order_acquire); }
    void set_prunable_hash_valid(bool v) const { prunable_hash_valid.store(v,std::memory_order_release); }
    bool is_blob_size_valid() const { return blob_size_valid.load(std::memory_order_acquire); }
    void set_blob_size_valid(bool v) const { blob_size_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) const { hash = h; set_hash_valid(true); }
    void set_prunable_hash(const crypto::hash &h) const { prunable_hash = h; set_prunable_hash_valid(true); }
    void set_blob_size(size_t sz) const { blob_size = sz; set_blob_size_valid(true); }

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
      {
        set_hash_valid(false);
        set_prunable_hash_valid(false);
        set_blob_size_valid(false);
      }

      const auto start_pos = ar.getpos();

      FIELDS(*static_cast<transaction_prefix *>(this))

      if (std::is_same<Archive<W>, binary_archive<W>>())
        prefix_size = ar.getpos() - start_pos;

      if (version == 1)
      {
        if (std::is_same<Archive<W>, binary_archive<W>>())
          unprunable_size = ar.getpos() - start_pos;

        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        if (!pruned) for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.good()) return false;
          ar.end_object();

          if (std::is_same<Archive<W>, binary_archive<W>>())
            unprunable_size = ar.getpos() - start_pos;

          if (!pruned && rct_signatures.type != rct::RCTTypeNull)
          {
            ar.tag("rctsig_prunable");
            ar.begin_object();
            r = rct_signatures.p.serialize_rctsig_prunable(ar, rct_signatures.type, vin.size(), vout.size(),
                vin.size() > 0 && vin[0].type() == typeid(txin_haven_key) ? boost::get<txin_haven_key>(vin[0]).key_offsets.size() - 1 : 0);
            if (!r || !ar.good()) return false;
            ar.end_object();
          }
        }
      }
      if (!typename Archive<W>::is_saving())
        pruned = false;
    END_SERIALIZE()

    template<bool W, template <bool> class Archive>
    bool serialize_base(Archive<W> &ar)
    {
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1)
      {
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_object();
          bool r = rct_signatures.serialize_rctsig_base(ar, vin.size(), vout.size());
          if (!r || !ar.good()) return false;
          ar.end_object();
        }
      }
      if (!typename Archive<W>::is_saving())
        pruned = true;
      return ar.good();
    }

  private:
    static size_t get_signature_size(const txin_v& tx_in);
  };

  inline transaction::transaction(const transaction &t):
    transaction_prefix(t),
    hash_valid(false),
    prunable_hash_valid(false),
    blob_size_valid(false),
    signatures(t.signatures),
    rct_signatures(t.rct_signatures),
    pruned(t.pruned),
    unprunable_size(t.unprunable_size.load()),
    prefix_size(t.prefix_size.load())
  {
    if (t.is_hash_valid())
    {
      hash = t.hash;
      set_hash_valid(true);
    }
    if (t.is_blob_size_valid())
    {
      blob_size = t.blob_size;
      set_blob_size_valid(true);
    }
    if (t.is_prunable_hash_valid())
    {
      prunable_hash = t.prunable_hash;
      set_prunable_hash_valid(true);
    }
  }

  inline transaction &transaction::operator=(const transaction &t)
  {
    transaction_prefix::operator=(t);

    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
    signatures = t.signatures;
    rct_signatures = t.rct_signatures;
    if (t.is_hash_valid())
    {
      hash = t.hash;
      set_hash_valid(true);
    }
    if (t.is_prunable_hash_valid())
    {
      prunable_hash = t.prunable_hash;
      set_prunable_hash_valid(true);
    }
    if (t.is_blob_size_valid())
    {
      blob_size = t.blob_size;
      set_blob_size_valid(true);
    }
    pruned = t.pruned;
    unprunable_size = t.unprunable_size.load();
    prefix_size = t.prefix_size.load();
    return *this;
  }

  inline
  transaction::transaction()
  {
    set_null();
  }

  inline
  transaction::~transaction()
  {
  }

  inline
  void transaction::set_null()
  {
    transaction_prefix::set_null();
    signatures.clear();
    rct_signatures.type = rct::RCTTypeNull;
    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
    pruned = false;
    unprunable_size = 0;
    prefix_size = 0;
  }

  inline
  void transaction::invalidate_hashes()
  {
    set_hash_valid(false);
    set_prunable_hash_valid(false);
    set_blob_size_valid(false);
  }

  inline
  size_t transaction::get_signature_size(const txin_v& tx_in)
  {
    struct txin_signature_size_visitor : public boost::static_visitor<size_t>
    {
      size_t operator()(const txin_gen& txin) const{return 0;}
      size_t operator()(const txin_to_script& txin) const{return 0;}
      size_t operator()(const txin_to_scripthash& txin) const{return 0;}
      size_t operator()(const txin_to_key& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_offshore& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_onshore& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_xasset& txin) const {return txin.key_offsets.size();}
      size_t operator()(const txin_haven_key& txin) const {return txin.key_offsets.size();}
    };

    return boost::apply_visitor(txin_signature_size_visitor(), tx_in);
  }


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct block_header
  {
    uint8_t major_version;
    uint8_t minor_version;  // now used as a voting mechanism, rather than how this particular block is built
    uint64_t timestamp;
    crypto::hash  prev_id;
    uint32_t nonce;
    offshore::pricing_record pricing_record;

    BEGIN_SERIALIZE()
      VARINT_FIELD(major_version)
      VARINT_FIELD(minor_version)
      VARINT_FIELD(timestamp)
      FIELD(prev_id)
      FIELD(nonce)
      if (major_version >= HF_VERSION_OFFSHORE_PRICING)
      {
        if (major_version < HF_VERSION_XASSET_FEES_V2)
        {
          offshore::pricing_record_v1 pr_v1;
          if (!typename Archive<W>::is_saving())
          {
            FIELD(pr_v1)
            pr_v1.write_to_pr(pricing_record);
          }
          else
          {
            pr_v1.read_from_pr(pricing_record);
            FIELD(pr_v1)
          }
        }
        else
        {
          FIELD(pricing_record)
        }
      }
    END_SERIALIZE()
  };

  struct block: public block_header
  {
  private:
    // hash cash
    mutable std::atomic<bool> hash_valid;

  public:
    block(): block_header(), hash_valid(false) {}
    block(const block &b): block_header(b), hash_valid(false), miner_tx(b.miner_tx), tx_hashes(b.tx_hashes) { if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } }
    block &operator=(const block &b) { block_header::operator=(b); hash_valid = false; miner_tx = b.miner_tx; tx_hashes = b.tx_hashes; if (b.is_hash_valid()) { hash = b.hash; set_hash_valid(true); } return *this; }
    void invalidate_hashes() { set_hash_valid(false); }
    bool is_hash_valid() const { return hash_valid.load(std::memory_order_acquire); }
    void set_hash_valid(bool v) const { hash_valid.store(v,std::memory_order_release); }
    void set_hash(const crypto::hash &h) const { hash = h; set_hash_valid(true); }

    transaction miner_tx;
    std::vector<crypto::hash> tx_hashes;

    // hash cash
    mutable crypto::hash hash;

    BEGIN_SERIALIZE_OBJECT()
      if (!typename Archive<W>::is_saving())
        set_hash_valid(false);

      FIELDS(*static_cast<block_header *>(this))
      FIELD(miner_tx)
      FIELD(tx_hashes)
      if (tx_hashes.size() > CRYPTONOTE_MAX_TX_PER_BLOCK)
        return false;
    END_SERIALIZE()
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct account_public_address
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_spend_public_key)
      KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(m_view_public_key)
    END_KV_SERIALIZE_MAP()

    bool operator==(const account_public_address& rhs) const
    {
      return m_spend_public_key == rhs.m_spend_public_key &&
             m_view_public_key == rhs.m_view_public_key;
    }

    bool operator!=(const account_public_address& rhs) const
    {
      return !(*this == rhs);
    }
  };

  struct keypair
  {
    crypto::public_key pub;
    crypto::secret_key sec;

    static inline keypair generate(hw::device &hwdev)
    {
      keypair k;
      hwdev.generate_keys(k.pub, k.sec);
      return k;
    }
  };
  //---------------------------------------------------------------

}

namespace std {
  template <>
  struct hash<cryptonote::account_public_address>
  {
    std::size_t operator()(const cryptonote::account_public_address& addr) const
    {
      // https://stackoverflow.com/a/17017281
      size_t res = 17;
      res = res * 31 + hash<crypto::public_key>()(addr.m_spend_public_key);
      res = res * 31 + hash<crypto::public_key>()(addr.m_view_public_key);
      return res;
    }
  };
}

BLOB_SERIALIZER(cryptonote::txout_to_key);
BLOB_SERIALIZER(cryptonote::txout_offshore);
BLOB_SERIALIZER(cryptonote::txout_to_scripthash);

VARIANT_TAG(binary_archive, cryptonote::txin_gen, 0xff);
VARIANT_TAG(binary_archive, cryptonote::txin_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txin_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txin_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txin_offshore, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txin_onshore, 0x4);
VARIANT_TAG(binary_archive, cryptonote::txin_xasset, 0x5);
VARIANT_TAG(binary_archive, cryptonote::txin_haven_key, 0x6);
VARIANT_TAG(binary_archive, cryptonote::txout_to_script, 0x0);
VARIANT_TAG(binary_archive, cryptonote::txout_to_scripthash, 0x1);
VARIANT_TAG(binary_archive, cryptonote::txout_to_key, 0x2);
VARIANT_TAG(binary_archive, cryptonote::txout_offshore, 0x3);
VARIANT_TAG(binary_archive, cryptonote::txout_xasset, 0x5);
VARIANT_TAG(binary_archive, cryptonote::txout_haven_key, 0x6);
VARIANT_TAG(binary_archive, cryptonote::txout_haven_tagged_key, 0x7);
VARIANT_TAG(binary_archive, cryptonote::transaction, 0xcc);
VARIANT_TAG(binary_archive, cryptonote::block, 0xbb);

VARIANT_TAG(json_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(json_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::txin_offshore, "offshore");
VARIANT_TAG(json_archive, cryptonote::txin_onshore, "onshore");
VARIANT_TAG(json_archive, cryptonote::txin_xasset, "xasset");
VARIANT_TAG(json_archive, cryptonote::txin_haven_key, "haven_key");
VARIANT_TAG(json_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(json_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(json_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(json_archive, cryptonote::txout_offshore, "offshore");
VARIANT_TAG(json_archive, cryptonote::txout_xasset, "xasset");
VARIANT_TAG(json_archive, cryptonote::txout_haven_key, "haven_key");
VARIANT_TAG(json_archive, cryptonote::txout_haven_tagged_key, "haven_tagged_key");
VARIANT_TAG(json_archive, cryptonote::transaction, "tx");
VARIANT_TAG(json_archive, cryptonote::block, "block");

VARIANT_TAG(debug_archive, cryptonote::txin_gen, "gen");
VARIANT_TAG(debug_archive, cryptonote::txin_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txin_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txin_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::txin_offshore, "offshore");
VARIANT_TAG(debug_archive, cryptonote::txin_onshore, "onshore");
VARIANT_TAG(debug_archive, cryptonote::txin_xasset, "xasset");
VARIANT_TAG(debug_archive, cryptonote::txin_haven_key, "haven_key");
VARIANT_TAG(debug_archive, cryptonote::txout_to_script, "script");
VARIANT_TAG(debug_archive, cryptonote::txout_to_scripthash, "scripthash");
VARIANT_TAG(debug_archive, cryptonote::txout_to_key, "key");
VARIANT_TAG(debug_archive, cryptonote::txout_offshore, "offshore");
VARIANT_TAG(debug_archive, cryptonote::txout_xasset, "xasset");
VARIANT_TAG(debug_archive, cryptonote::txout_haven_key, "haven_key");
VARIANT_TAG(debug_archive, cryptonote::txout_haven_tagged_key, "haven_tagged_key");
VARIANT_TAG(debug_archive, cryptonote::transaction, "tx");
VARIANT_TAG(debug_archive, cryptonote::block, "block");
