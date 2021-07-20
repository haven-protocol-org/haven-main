// Copyright (c) 2021, Haven Protocol
// Portions copyright (c) 2014-2019, The Monero Project
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

#include <boost/algorithm/string.hpp>
#include "common/command_line.h"
#include "common/varint.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/blockchain.h"
#include "blockchain_db/blockchain_db.h"
#include "offshore/pricing_record.h"
#include "version.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bcutil"

#define DELIM "|"

namespace po = boost::program_options;
using namespace epee;
using namespace cryptonote;

static bool stop_requested = false;

int main(int argc, char* argv[])
{
  TRY_ENTRY();

  epee::string_tools::set_module_name_and_folder(argv[0]);

  uint32_t log_level = 0;
  uint64_t block_start = 0;
  uint64_t block_stop = 0;

  tools::on_startup();

  boost::filesystem::path output_file_path;

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<std::string> arg_log_level  = {"log-level",  "0-4 or categories", ""};
  const command_line::arg_descriptor<uint64_t> arg_block_start  = {"block-start", "start at block number", block_start};
  const command_line::arg_descriptor<uint64_t> arg_block_stop = {"block-stop", "Stop at block number", block_stop};
  const command_line::arg_descriptor<std::string> arg_delimiter  = {"delimiter", "\"<string>\"", DELIM};

  command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
  command_line::add_arg(desc_cmd_sett, cryptonote::arg_stagenet_on);
  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_block_start);
  command_line::add_arg(desc_cmd_sett, arg_block_stop);
  command_line::add_arg(desc_cmd_sett, arg_delimiter);
  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    auto parser = po::command_line_parser(argc, argv).options(desc_options);
    po::store(parser.run(), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Haven '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
    std::cout << desc_options << std::endl;
    return 1;
  }

  mlog_configure(mlog_get_default_log_path("haven-blockchain-scanner.log"), true);
  if (!command_line::is_arg_defaulted(vm, arg_log_level))
    mlog_set_log(command_line::get_arg(vm, arg_log_level).c_str());
  else
    mlog_set_log(std::string(std::to_string(log_level) + ",bcutil:INFO").c_str());

  LOG_PRINT_L0("Starting...");

  std::string opt_data_dir = command_line::get_arg(vm, cryptonote::arg_data_dir);
  bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
  bool opt_stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
  network_type net_type = opt_testnet ? TESTNET : opt_stagenet ? STAGENET : MAINNET;
  block_start = command_line::get_arg(vm, arg_block_start);
  block_stop = command_line::get_arg(vm, arg_block_stop);
  std::string delimiter = command_line::get_arg(vm, arg_delimiter);

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");
  std::unique_ptr<Blockchain> core_storage;
  tx_memory_pool m_mempool(*core_storage);
  core_storage.reset(new Blockchain(m_mempool));
  BlockchainDB *db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }

  boost::filesystem::path folder(opt_data_dir);
  if (opt_stagenet) {
    folder /= std::to_string(STAGENET_VERSION);
  } else if (opt_testnet) {
    folder /= std::to_string(TESTNET_VERSION);
  }
  folder /= db->get_db_name();
  LOG_PRINT_L0("Loading blockchain from folder " << folder << " ...");
  const std::string filename = folder.string();

  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return 1;
  }
  r = core_storage->init(db, net_type);

  CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
  LOG_PRINT_L0("Source blockchain storage initialized OK");

  tools::signal_handler::install([](int type) {
    stop_requested = true;
  });

  const uint64_t db_height = db->height();
  if (!block_stop)
      block_stop = db_height;
  MINFO("Starting from height " << block_start << ", stopping at height " << block_stop);

/*
 * The default output can be plotted with GnuPlot using these commands:
set key autotitle columnhead
set title "Haven Blockchain Growth"
set timefmt "%Y-%m-%d"
set xdata time
set xrange ["2014-04-17":*]
set format x "%Y-%m-%d"
set yrange [0:*]
set y2range [0:*]
set ylabel "Txs/Day"
set y2label "Bytes"
set y2tics nomirror
plot 'stats.csv' index "DATA" using (timecolumn(1,"%Y-%m-%d")):4 with lines, '' using (timecolumn(1,"%Y-%m-%d")):7 axes x1y2 with lines
 */

  // spit out a comment that GnuPlot can use as an index
  std::cout << ENDL << "# DATA" << ENDL;
  std::cout << "Date" << delimiter << "Height" << delimiter << "Transaction ID" << delimiter << "Reason" << delimiter << "Extra Information";
  std::cout << ENDL;

#define MAX_INOUT	0xffffffff
#define MAX_RINGS	0xffffffff

  struct tm prevtm = {0}, currtm;
  uint64_t prevsz = 0, currsz = 0;
  uint64_t prevtxs = 0, currtxs = 0;
  uint64_t currblks = 0;
  uint32_t txhr[24] = {0};
  unsigned int i;

  for (uint64_t h = block_start; h < block_stop; ++h)
  {
    cryptonote::blobdata bd = db->get_block_blob_from_height(h);
    cryptonote::block blk;
    if (!cryptonote::parse_and_validate_block_from_blob(bd, blk))
    {
      LOG_PRINT_L0("Bad block from db");
      return 1;
    }
    time_t tt = blk.timestamp;
    char timebuf[64];
    epee::misc_utils::get_gmt_time(tt, currtm);
    if (!prevtm.tm_year)
      prevtm = currtm;
    // catch change of day
    if (currtm.tm_mday > prevtm.tm_mday || (currtm.tm_mday == 1 && prevtm.tm_mday > 27))
    {
      // check for timestamp fudging around month ends
      if (prevtm.tm_mday == 1 && currtm.tm_mday > 27)
        goto skip;
      strftime(timebuf, sizeof(timebuf), "%Y-%m-%d", &currtm);
      prevtm = currtm;
    }
skip:
    currsz += bd.size();
    uint64_t coinbase_amount;
    uint64_t tx_fee_amount = 0;
    std::set<std::string> used_assets, miner_tx_assets;
    used_assets.insert("XHV");

    // Get the miner_tx assets
    for (const auto& miner_tx_vout : blk.miner_tx.vout) {
      if (miner_tx_vout.target.type() == typeid(txout_to_key)) {
        miner_tx_assets.insert("XHV");
      } else if (miner_tx_vout.target.type() == typeid(txout_offshore)) {
        miner_tx_assets.insert("XUSD");
      } else if (miner_tx_vout.target.type() == typeid(txout_xasset)) {
        miner_tx_assets.insert(boost::get<cryptonote::txout_xasset>(miner_tx_vout.target).asset_type);
      } else {
        throw std::runtime_error("Aborting: miner_tx contains invalid vout type");
      }
    }

    for (const auto& tx_id : blk.tx_hashes)
    {
      if (tx_id == crypto::null_hash)
      {
        throw std::runtime_error("Aborting: tx == null_hash");
      }
      if (!db->get_pruned_tx_blob(tx_id, bd))
      {
        throw std::runtime_error("Aborting: tx not found");
      }
      transaction tx;
      if (!parse_and_validate_tx_base_from_blob(bd, tx))
      {
        LOG_PRINT_L0("Bad txn from db");
        return 1;
      }
      currsz += bd.size();
      if (db->get_prunable_tx_blob(tx_id, bd))
        currsz += bd.size();
      currtxs++;

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
      if (!cryptonote::get_tx_asset_types(tx, tx.hash, source, dest, false)) {
        std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "At least 1 input or 1 output of the tx was invalid" << delimiter << "get_tx_asset_types() failed : ";
        if (source.empty()) {
          std::cout << "source is empty" << std::endl;
        }
        if (dest.empty()) {
          std::cout << "dest is empty" << std::endl;
        }
      }
      if (!cryptonote::get_tx_type(source, dest, offshore, onshore, offshore_transfer, xusd_to_xasset, xasset_to_xusd, xasset_transfer)) {
        std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "At least 1 input or 1 output of the tx was invalid" << delimiter << "get_tx_type() failed" << std::endl;
      }

      // Add the source currency to the list of expected ones
      used_assets.insert(source);
        
      if ((offshore && !tx.rct_signatures.txnOffshoreFee) ||
          (onshore && !tx.rct_signatures.txnOffshoreFee_usd) ||
          (xusd_to_xasset && !tx.rct_signatures.txnOffshoreFee_usd) ||
          (xasset_to_xusd && !tx.rct_signatures.txnOffshoreFee_xasset)) {
        std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "Missing conversion fee." << delimiter << "" <<
          "Source:" << source << ", dest:" << dest <<
          ", XHV fees:" << tx.rct_signatures.txnFee << "," << tx.rct_signatures.txnOffshoreFee <<
          ", XUSD fees:" << tx.rct_signatures.txnFee_usd << "," << tx.rct_signatures.txnOffshoreFee_usd <<
          ", burnt:" << tx.amount_burnt << ", minted:" << tx.amount_minted << std::endl;
      } else if ((offshore || onshore || xusd_to_xasset || xasset_to_xusd) && (!tx.amount_burnt || !tx.amount_minted)) {
        std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "Missing burnt/minted value." << std::endl;
      }

      // Only run these checks for conversions
      if (source != dest) {

        // Check PR record is not too old
        if (h > (tx.pricing_record_height + 10)) {
          std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "pricing record used by tx was too old" <<
            delimiter << "tx.pricing_record_height = " << tx.pricing_record_height << std::endl;
        }

        // Get the PR used by the TX
        cryptonote::blobdata bd_pr = db->get_block_blob_from_height(tx.pricing_record_height);
        cryptonote::block blk_pr;
        if (!cryptonote::parse_and_validate_block_from_blob(bd_pr, blk_pr)) {
          LOG_PRINT_L0("Bad block from db");
          return 1;
        }

        // Get a more convenient handle on the conversion PR
        pr = blk_pr.pricing_record;
        
        // Verify the fees in 128-bit space
        boost::multiprecision::uint128_t burnt_128 = tx.amount_burnt;
        boost::multiprecision::uint128_t minted_128 = tx.amount_minted;

        // calculate conversion fees
        uint32_t fees_version = (h >= 831700) ? 2 : (h >= 653565) ? 2 : 1;
        uint64_t blocks_to_unlock = tx.unlock_time - h + 1;

        boost::multiprecision::uint128_t fee;
        if (offshore) {
          if (fees_version >= 3) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid fee version " << fees_version << "" << delimiter << "..." << std::endl;
          } else if (fees_version == 2) {

            fee = 
              (blocks_to_unlock >= 5030) ? (tx.amount_burnt / 500) :
              (blocks_to_unlock >= 1430) ? (tx.amount_burnt / 20) :
              (blocks_to_unlock >= 710) ? (tx.amount_burnt / 10) :
              tx.amount_burnt / 5;

          } else {

            // Calculate the priority based on the unlock time
            uint64_t priority =
              (blocks_to_unlock >= 5030) ? 1 :
              (blocks_to_unlock >= 1430) ? 2 :
              (blocks_to_unlock >= 710) ? 3 :
              4;
            uint64_t unlock_time = 60 * pow(3, 4-priority);

            // abs() implementation for uint64_t's
            uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;

            // Estimate the fee
            double scale = exp((M_PI / -1000.0) * (unlock_time - 60) * 1.2);
            scale *= delta;
            scale *= tx.amount_burnt;
            scale /= 1000000000000;
            fee = (boost::multiprecision::uint128_t)(scale);
          }

          if ((h >= 658500) && (fee != tx.rct_signatures.txnOffshoreFee)) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid fee " << tx.rct_signatures.txnOffshoreFee << "" << delimiter << "check:" << fee << std::endl;
          }
        
        } else if (onshore) {
          
          if (fees_version >= 3) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid fee version " << fees_version << "" << delimiter << "..." << std::endl;
          } else if (fees_version == 2) {

            fee = 
              (blocks_to_unlock >= 5030) ? (tx.amount_burnt / 500) :
              (blocks_to_unlock >= 1430) ? (tx.amount_burnt / 20) :
              (blocks_to_unlock >= 710) ? (tx.amount_burnt / 10) :
              tx.amount_burnt / 5;
            
          } else {
            
            // Calculate the priority based on the unlock time
            uint64_t priority =
              (blocks_to_unlock >= 5030) ? 1 :
              (blocks_to_unlock >= 1430) ? 2 :
              (blocks_to_unlock >= 710) ? 3 :
              4;
            uint64_t unlock_time = 60 * pow(3, 4-priority);

            // abs() implementation for uint64_t's
            uint64_t delta = (pr.unused1 > pr.xUSD) ? pr.unused1 - pr.xUSD : pr.xUSD - pr.unused1;

            // Estimate the fee
            double scale = exp((M_PI / -1000.0) * (unlock_time - 60) * 1.2);
            scale *= delta;
            scale *= tx.amount_burnt;
            scale /= 1000000000000;
            fee = (boost::multiprecision::uint128_t)(scale);
          }

          if ((h >= 658500) && (fee != tx.rct_signatures.txnOffshoreFee_usd)) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid offshore fee " << tx.rct_signatures.txnOffshoreFee_usd << "" << delimiter << "check:" << fee << std::endl;
          }

        } else if (xusd_to_xasset) {

          fee = tx.amount_burnt;
          fee *= 3;
          fee /= 1000;
          
          if (fee != tx.rct_signatures.txnOffshoreFee_usd) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid xusd_to_xasset fee " << tx.rct_signatures.txnOffshoreFee_usd << "" << delimiter << "check:" << fee << std::endl;
          }

        } else if (xasset_to_xusd) {

          fee = tx.amount_burnt;
          fee *= 3;
          fee /= 1000;
          
          if (fee != tx.rct_signatures.txnOffshoreFee_xasset) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter
                      << "invalid xasset_to_xusd fee " << tx.rct_signatures.txnOffshoreFee_xasset << "" << delimiter << "check:" << fee << std::endl;
          }

        }
        
        // Check for 0 price in the source or destination currency
        if (offshore|| xusd_to_xasset) {
          if (!pr[dest]) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "0 exchange rate used for dest " << dest << "" << delimiter << "..." << std::endl;
          } else if (pr[dest] == 1000000000000) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "1.0000 exchange rate used for dest " << dest << "" << delimiter << "..." << std::endl;
          }
        } else if (onshore || xasset_to_xusd) {
          if (!pr[source]) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "0 exchange rate used for source " << source << "" << delimiter << "..." << std::endl;
          } else if (pr[source] == 1000000000000) {
            std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << tx_id << "" << delimiter << "1.0000 exchange rate used for source " << source << "" << delimiter << "..." << std::endl;
          }
        }
      }
    }

    // compare the asset sets
    if (used_assets == miner_tx_assets) {
    } else if (used_assets.empty() && (miner_tx_assets.size() == 1) && (miner_tx_assets.count("XHV") == 1)) {
    } else {
      std::cout << timebuf << "" << delimiter << "" << h << "" << delimiter << "" << blk.miner_tx.hash << "" << delimiter << "Mismatch in miner reward assets detected" << delimiter << "Used assets = { ";
      for (auto const &i: used_assets)
        std::cout << i << " ";
      std::cout << "}, miner_tx claimed { ";
      for (auto const &i: miner_tx_assets)
        std::cout << i << " ";
      std::cout << "}" << std::endl;
    }
    
    currblks++;

    if (stop_requested)
      break;
  }

  core_storage->deinit();
  return 0;

  CATCH_ENTRY("Stats reporting error", 1);
}
