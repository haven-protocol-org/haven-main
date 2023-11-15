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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <boost/system/error_code.hpp>
#include <boost/filesystem.hpp>
#include <functional>
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str, const std::string& difficulty_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    if (!difficulty_str.empty())
    {
      try
      {
        difficulty_type difficulty(difficulty_str);
        if (m_difficulty_points.count(height))
        {
          CHECK_AND_ASSERT_MES(difficulty == m_difficulty_points[height], false, "Difficulty checkpoint at given height already exists, and difficulty for new checkpoint was different!");
        }
        m_difficulty_points[height] = difficulty;
      }
      catch (...)
      {
        LOG_ERROR("Failed to parse difficulty checkpoint: " << difficulty_str);
        return false;
      }
    }
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    if (m_points.empty())
      return 0;
    return m_points.rbegin()->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, difficulty_type>& checkpoints::get_difficulty_points() const
  {
    return m_difficulty_points;
  }

  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == MAINNET) {
      ADD_CHECKPOINT(886575, "9c3cffaf1b68fe64df5668ca966102a6b345bb82364305bd510fe75a566296fb");
      ADD_CHECKPOINT2(1, "504a9f2becf14b512c37415ad3ab7f8bf914589ecbc501b82448c34c18f816b1", "0x2" /* 2 */);
      ADD_CHECKPOINT2(10, "37b5cb3c5ca2171286be97e3345ba056a5e2d5cad3b4f1c0afeb78a9133a038e", "0x132" /* 306 */);
      ADD_CHECKPOINT2(100, "16d5fd4bbff3e7105c8594fff4e67719efdf2a9bb776db0ff2de02f36ec3d3a2", "0xa0d4e" /* 658766 */);
      ADD_CHECKPOINT2(1000, "5515df00f85714d4c439d26e090c69273b65e6260607c68d9ba4d44913cc07e4", "0x7901e1" /* 7930337 */);
      ADD_CHECKPOINT2(10000, "10241e1f44523d46cc20c75c08e94847c35e6dcc4bb6eca921034048e550c850", "0x3A7DAB02851" /* 4019463399505 */);
      ADD_CHECKPOINT2(50000, "ae4fe5e5a079ac668e67de7b82f4a1cd210424c84dfb274b72298fc82ed33838", "0x2D0E6172D700" /* 49539787708160 */);
      ADD_CHECKPOINT2(100000, "fc5261f1082ac90b8c71288a482127447c0eb2c95b9f37224944c5b0f880bc20", "0xA62942B2599F" /* 182696142854559 */);
      ADD_CHECKPOINT2(200000, "3e868a3716e27394fdfb3ad642efdc2d46ab3522da22760a70f8a3b5bdeff2e3", "0x19A74E60EDBD4" /* 451301843327956 */);
      ADD_CHECKPOINT2(300000, "e2dc138258112c9b661d45fa406cd4f101226b8f3405caa84890a2d2fa9d50be", "0x2B0101892C0D4" /* 756533131657428 */);
      ADD_CHECKPOINT2(400000, "effca065ad810a00ae310eca39be6f56c0968894acc077fe56e5dc41c2789e7a", "0x3279BBDD58334" /* 887974788432692 */);
      ADD_CHECKPOINT2(500000, "f7a46424d5b24eff8a6f7c8afd4c90b6e23fc869059110768bd11b9897c666b5", "0x36CBEC91DA707" /* 963991603881735 */);
      ADD_CHECKPOINT2(600000, "774f3e78a1728000cc06caca67c4e6a5600056a50bb15877d952220d01f13b38", "0x3E286CDED3D2F" /* 1093493538503983 */);
      ADD_CHECKPOINT2(700000, "5362de22aa57105af334537ec2fb902d1af661aacdad43d4e98a30f0132d3e67", "0x49168FB73577B" /* 1285779988109179 */);
      ADD_CHECKPOINT2(800000, "6e608a6ebb7e844d37416f8ddb8ed4fbae783ff2e9cd5609b9b06e9a7d86986b", "0x584C5A0B51C3E" /* 1553359223200830 */);
      ADD_CHECKPOINT2(900000, "331d4f8ad4b4bff47be3b669a75f273fcedcbfe7e169e85bccd2239640b684e9", "0x74831A2C143EE" /* 2049702858146798 */);
      ADD_CHECKPOINT2(1000000, "cdf86feacda2af448ce89773e888802dc6e44f4bddd6f558c4e2a1e319f24e84", "0x8A4A16B30A914" /* 2432813008726292 */);
      ADD_CHECKPOINT2(1100000, "3c3eef47f84b70e9297ba5e4b30cfcafb816962ef0c794045b13210151207938", "0x9EE730E027358" /* 2795452714087256 */);
      ADD_CHECKPOINT2(1200000, "f0c75e0631510e6c741cba00aa13906391a0e9735396353186b0441a5ece3c8d", "0xA722731E203D3" /* 2940262433293267 */);
      ADD_CHECKPOINT2(1300000, "8b0d2db522fd314624fc07edde76d401952106ad7ea605ceb3bc82c8e65af261", "0xAF77661904348" /* 3086837582152520 */);
      ADD_CHECKPOINT2(1400000, "fc6a5ead2cfb4e1a2f322ed22dc6d80038c8378ff5f320aa8aa6ecf1900546db", "0xB4DCD5666651B" /* 3181769057002779 */);
    }
    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
    };

    static const std::vector<std::string> testnet_dns_urls = {
    };

    static const std::vector<std::string> stagenet_dns_urls = {
    };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::hex_to_pod(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
