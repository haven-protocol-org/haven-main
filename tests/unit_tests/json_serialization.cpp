
#include <boost/optional/optional.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <vector>

#include "byte_stream.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "serialization/json_object.h"


// Rapidjson isnt being used for tx serialization
// namespace
// {
//     cryptonote::transaction
//     make_miner_transaction(cryptonote::account_public_address const& to)
//     {
//         cryptonote::transaction tx{};
//         std::map<std::string, uint64_t> fee_map, offshore_fee_map, xasset_fee_map;
//         fee_map["XHV"] = 0;
//         if (!cryptonote::construct_miner_tx(0, 0, 5000, 500, fee_map, offshore_fee_map, xasset_fee_map, to, tx))
//             throw std::runtime_error{"transaction construction error"};

//         crypto::hash id{0};
//         if (!cryptonote::get_transaction_hash(tx, id))
//             throw std::runtime_error{"could not get transaction hash"};

//         return tx;
//     }

//     cryptonote::transaction
//     make_transaction(
//         cryptonote::account_keys const& from,
//         std::vector<cryptonote::transaction> const& sources,
//         std::vector<cryptonote::account_public_address> const& destinations,
//         uint64_t current_height,
//         uint64_t unlock_time,
//         cryptonote::transaction_type tx_type,
//         std::string source,
//         std::string dest,
//         offshore::pricing_record pr,
//         uint32_t fees_version,
//         uint32_t hf_version,
//         bool rct,
//         bool bulletproof)
//     {
//         std::uint64_t source_amount = 0;
//         std::vector<cryptonote::tx_source_entry> actual_sources;
//         for (auto const& source : sources)
//         {
//             std::vector<cryptonote::tx_extra_field> extra_fields;
//             if (!cryptonote::parse_tx_extra(source.extra, extra_fields))
//                 throw std::runtime_error{"invalid transaction"};

//             cryptonote::tx_extra_pub_key key_field{};
//             if (!cryptonote::find_tx_extra_field_by_type(extra_fields, key_field))
//                 throw std::runtime_error{"invalid transaction"};

//             for (auto const& input : boost::adaptors::index(source.vout))
//             {
//                 source_amount += input.value().amount;
//                 auto const& key = boost::get<cryptonote::txout_to_key>(input.value().target);

//                 actual_sources.push_back(
//                     {{}, 0, key_field.pub_key, {}, std::size_t(input.index()), input.value().amount, rct, rct::identity()}
//                 );

//                 for (unsigned ring = 0; ring < 10; ++ring)
//                     actual_sources.back().push_output(input.index(), key.key, input.value().amount);
//             }
//         }

//         std::vector<cryptonote::tx_destination_entry> to;
//         for (auto const& destination : destinations)
//             to.push_back({(source_amount / destinations.size()), destination, false});

//         cryptonote::transaction tx{};

//         crypto::secret_key tx_key{};
//         std::vector<crypto::secret_key> extra_keys{};

//         std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
//         subaddresses[from.m_account_address.m_spend_public_key] = {0,0};

//         if (!cryptonote::construct_tx_and_get_tx_key(from, subaddresses, actual_sources, to, boost::none, {}, tx, tx_type, source, dest, unlock_time, tx_key, extra_keys, current_height, pr, fees_version, hf_version, rct, { bulletproof ? rct::RangeProofBulletproof : rct::RangeProofBorromean, bulletproof ? 2 : 0 }))
//             throw std::runtime_error{"transaction construction error"};

//         return tx;
//     }

//     template<typename T>
//     T test_json(const T& value)
//     {
//       epee::byte_stream buffer;
//       {
//         rapidjson::Writer<epee::byte_stream> dest{buffer};
//         cryptonote::json::toJsonValue(dest, value);
//       }

//       rapidjson::Document doc;
//       doc.Parse(reinterpret_cast<const char*>(buffer.data()), buffer.size());
//       if (doc.HasParseError() || !doc.IsObject())
//       {
//         throw cryptonote::json::PARSE_FAIL();
//       }

//       T out{};
//       cryptonote::json::fromJsonValue(doc, out);
//       return out;
//     }
// } // anonymous

// TEST(JsonSerialization, MinerTransaction)
// {
//     cryptonote::account_base acct;
//     acct.generate();
//     const auto miner_tx = make_miner_transaction(acct.get_keys().m_account_address);

//     crypto::hash tx_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx, tx_hash));

//     cryptonote::transaction miner_tx_copy = test_json(miner_tx);

//     crypto::hash tx_copy_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(miner_tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     cryptonote::blobdata tx_bytes{};
//     cryptonote::blobdata tx_copy_bytes{};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(miner_tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
// }

// TEST(JsonSerialization, RegularTransaction)
// {
//     cryptonote::account_base acct1;
//     acct1.generate();

//     cryptonote::account_base acct2;
//     acct2.generate();

//     const offshore::pricing_record pr;
//     const uint64_t height = 1;
//     const uint64_t unlock_time = 0;
//     const uint32_t fees_version = 3;
//     const uint32_t hf_version = 17;
//     std::string source = "XHV";
//     std::string dest = "XHV";
//     cryptonote::transaction_type tx_type = cryptonote::transaction_type::TRANSFER;
//     const auto miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     const auto tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, false, false);

//     crypto::hash tx_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     cryptonote::transaction tx_copy = test_json(tx);

//     crypto::hash tx_copy_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     cryptonote::blobdata tx_bytes{};
//     cryptonote::blobdata tx_copy_bytes{};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
// }

// TEST(JsonSerialization, RingctTransaction)
// {
//     cryptonote::account_base acct1;
//     acct1.generate();

//     cryptonote::account_base acct2;
//     acct2.generate();

//     const offshore::pricing_record pr;
//     const uint64_t height = 1;
//     const uint64_t unlock_time = 0;
//     const uint32_t fees_version = 3;
//     const uint32_t hf_version = 17;
//     std::string source = "XHV";
//     std::string dest = "XHV";
//     cryptonote::transaction_type tx_type = cryptonote::transaction_type::TRANSFER;
//     const auto miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     const auto tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, false);

//     crypto::hash tx_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     cryptonote::transaction tx_copy = test_json(tx);

//     crypto::hash tx_copy_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     cryptonote::blobdata tx_bytes{};
//     cryptonote::blobdata tx_copy_bytes{};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
// }

// TEST(JsonSerialization, BulletproofTransaction)
// {
//     // regular transfer
//     cryptonote::account_base acct1;
//     acct1.generate();

//     cryptonote::account_base acct2;
//     acct2.generate();

//     offshore::pricing_record pr;
//     uint64_t height = 1;
//     uint64_t unlock_time = 0;
//     uint32_t fees_version = 3;
//     uint32_t hf_version = 17;
//     std::string source = "XHV";
//     std::string dest = "XHV";
//     cryptonote::transaction_type tx_type = cryptonote::transaction_type::TRANSFER;
//     auto miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     auto tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     crypto::hash tx_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     cryptonote::transaction tx_copy = test_json(tx);

//     crypto::hash tx_copy_hash{};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     cryptonote::blobdata tx_bytes{};
//     cryptonote::blobdata tx_copy_bytes{};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);


//     // ofsfhore tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = height + 180;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XHV";
//     dest = "XUSD";
//     tx_type = cryptonote::transaction_type::OFFSHORE;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
    
//     // osnhore tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = height + 180;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XUSD";
//     dest = "XHV";
//     tx_type = cryptonote::transaction_type::ONSHORE;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
    
//     // ofsfhore transfer tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = 0;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XUSD";
//     dest = "XUSD";
//     tx_type = cryptonote::transaction_type::OFFSHORE_TRANSFER;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
    
//     // xusd_to_xasaset tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = height + 1440;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XUSD";
//     dest = "XBTC";
//     tx_type = cryptonote::transaction_type::XUSD_TO_XASSET;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
    
//     // xasset_to_xusd tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = height + 1440;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XBTC";
//     dest = "XUSD";
//     tx_type = cryptonote::transaction_type::XASSET_TO_XUSD;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);

//     // xasset_transfer tx
//     acct1.generate();
//     acct2.generate();

//     pr = {};
//     height = 1;
//     unlock_time = height + 0;
//     fees_version = 3;
//     hf_version = 17;
//     source = "XBTC";
//     dest = "XBTC";
//     tx_type = cryptonote::transaction_type::XASSET_TRANSFER;
//     miner_tx = make_miner_transaction(acct1.get_keys().m_account_address);
//     tx = make_transaction(acct1.get_keys(), {miner_tx}, {acct2.get_keys().m_account_address}, height, unlock_time, tx_type, source, dest, pr, fees_version, hf_version, true, true);

//     tx_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx, tx_hash));

//     tx_copy = test_json(tx);

//     tx_copy_hash = {};
//     ASSERT_TRUE(cryptonote::get_transaction_hash(tx_copy, tx_copy_hash));
//     EXPECT_EQ(tx_hash, tx_copy_hash);

//     tx_bytes = {};
//     tx_copy_bytes = {};

//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx, tx_bytes));
//     ASSERT_TRUE(cryptonote::t_serializable_object_to_blob(tx_copy, tx_copy_bytes));

//     EXPECT_EQ(tx_bytes, tx_copy_bytes);
// }

