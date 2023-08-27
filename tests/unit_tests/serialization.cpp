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

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <vector>
#include <boost/foreach.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "ringct/rctSigs.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/variant.h"
#include "serialization/containers.h"
#include "serialization/binary_utils.h"
#include "wallet/wallet2.h"
#include "gtest/gtest.h"
#include "unit_tests_utils.h"
#include "device/device.hpp"
using namespace std;
using namespace crypto;

struct Struct
{
  int32_t a;
  int32_t b;
  char blob[8];
};

template <class Archive>
struct serializer<Archive, Struct>
{
  static bool serialize(Archive &ar, Struct &s) {
    ar.begin_object();
    ar.tag("a");
    ar.serialize_int(s.a);
    ar.tag("b");
    ar.serialize_int(s.b);
    ar.tag("blob");
    ar.serialize_blob(s.blob, sizeof(s.blob));
    ar.end_object();
    return true;
  }
};

struct Struct1
{
  vector<boost::variant<Struct, int32_t>> si;
  vector<int16_t> vi;

  BEGIN_SERIALIZE_OBJECT()
    FIELD(si)
    FIELD(vi)
  END_SERIALIZE()
  /*template <bool W, template <bool> class Archive>
  bool do_serialize(Archive<W> &ar)
  {
    ar.begin_object();
    ar.tag("si");
    ::do_serialize(ar, si);
    ar.tag("vi");
    ::do_serialize(ar, vi);
    ar.end_object();
  }*/
};

struct Blob
{
  uint64_t a;
  uint32_t b;

  bool operator==(const Blob& rhs) const
  {
    return a == rhs.a;
  }
};

VARIANT_TAG(binary_archive, Struct, 0xe0);
VARIANT_TAG(binary_archive, int, 0xe1);
VARIANT_TAG(json_archive, Struct, "struct");
VARIANT_TAG(json_archive, int, "int");
VARIANT_TAG(debug_archive, Struct1, "struct1");
VARIANT_TAG(debug_archive, Struct, "struct");
VARIANT_TAG(debug_archive, int, "int");

BLOB_SERIALIZER(Blob);

bool try_parse(const string &blob)
{
  Struct1 s1;
  return serialization::parse_binary(blob, s1);
}

TEST(Serialization, BinaryArchiveInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_int(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(8, oss.str().size());
  ASSERT_EQ(string("\0\0\0\0\xff\0\0\0", 8), oss.str());

  const std::string s = oss.str();
  binary_archive<false> iar{epee::strspan<std::uint8_t>(s)};
  iar.serialize_int(x1);
  ASSERT_EQ(8, iar.getpos());
  ASSERT_TRUE(iar.good());

  ASSERT_EQ(x, x1);
}

TEST(Serialization, BinaryArchiveVarInts) {
  uint64_t x = 0xff00000000, x1;

  ostringstream oss;
  binary_archive<true> oar(oss);
  oar.serialize_varint(x);
  ASSERT_TRUE(oss.good());
  ASSERT_EQ(6, oss.str().size());
  ASSERT_EQ(string("\x80\x80\x80\x80\xF0\x1F", 6), oss.str());

  const std::string s = oss.str();
  binary_archive<false> iar{epee::strspan<std::uint8_t>(s)};
  iar.serialize_varint(x1);
  ASSERT_TRUE(iar.good());
  ASSERT_EQ(x, x1);
}

TEST(Serialization, Test1) {
  ostringstream str;
  binary_archive<true> ar(str);

  Struct1 s1;
  s1.si.push_back(0);
  {
    Struct s;
    s.a = 5;
    s.b = 65539;
    std::memcpy(s.blob, "12345678", 8);
    s1.si.push_back(s);
  }
  s1.si.push_back(1);
  s1.vi.push_back(10);
  s1.vi.push_back(22);

  string blob;
  ASSERT_TRUE(serialization::dump_binary(s1, blob));
  ASSERT_TRUE(try_parse(blob));

  ASSERT_EQ('\xE0', blob[6]);
  blob[6] = '\xE1';
  ASSERT_FALSE(try_parse(blob));
  blob[6] = '\xE2';
  ASSERT_FALSE(try_parse(blob));
}

TEST(Serialization, Overflow) {
  Blob x = { 0xff00000000 };
  Blob x1;

  string blob;
  ASSERT_TRUE(serialization::dump_binary(x, blob));
  ASSERT_EQ(sizeof(Blob), blob.size());

  ASSERT_TRUE(serialization::parse_binary(blob, x1));
  ASSERT_EQ(x, x1);

  vector<Blob> bigvector;
  ASSERT_FALSE(serialization::parse_binary(blob, bigvector));
  ASSERT_EQ(0, bigvector.size());
}

TEST(Serialization, serializes_vector_uint64_as_varint)
{
  std::vector<uint64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +1 byte
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(2, blob.size());

  // +1 byte
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(3, blob.size());

  // +2 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(5, blob.size());

  // +2 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(7, blob.size());

  // +2 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +3 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(12, blob.size());

  // +10 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(22, blob.size());
}

TEST(Serialization, serializes_vector_int64_as_fixed_int)
{
  std::vector<int64_t> v;
  string blob;

  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(1, blob.size());

  // +8 bytes
  v.push_back(0);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(9, blob.size());

  // +8 bytes
  v.push_back(1);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(17, blob.size());

  // +8 bytes
  v.push_back(0x80);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(25, blob.size());

  // +8 bytes
  v.push_back(0xFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(33, blob.size());

  // +8 bytes
  v.push_back(0x3FFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(41, blob.size());

  // +8 bytes
  v.push_back(0x40FF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(49, blob.size());

  // +8 bytes
  v.push_back(0xFFFFFFFFFFFFFFFF);
  ASSERT_TRUE(serialization::dump_binary(v, blob));
  ASSERT_EQ(57, blob.size());
}

namespace
{
  template<typename T>
  std::vector<T> linearize_vector2(const std::vector< std::vector<T> >& vec_vec)
  {
    std::vector<T> res;
    BOOST_FOREACH(const auto& vec, vec_vec)
    {
      res.insert(res.end(), vec.begin(), vec.end());
    }
    return res;
  }
}

TEST(Serialization, serializes_transacion_signatures_correctly)
{
  using namespace cryptonote;

  transaction tx;
  transaction tx1;
  string blob;

  // Empty tx
  tx.set_null();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(5, blob.size()); // 5 bytes + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx without signatures
  txin_gen txin_gen1;
  txin_gen1.height = 0;
  tx.set_null();
  tx.vin.push_back(txin_gen1);
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(7, blob.size()); // 5 bytes + 2 bytes vin[0] + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx with empty signatures 2nd vector
  tx.signatures.resize(1);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(7, blob.size()); // 5 bytes + 2 bytes vin[0] + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Miner tx with one signature
  tx.signatures[0].resize(1);
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Miner tx with 2 empty vectors
  tx.signatures.resize(2);
  tx.signatures[0].resize(0);
  tx.signatures[1].resize(0);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Miner tx with 2 signatures
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, no signatures
  tx.vin.push_back(txin_gen1);
  tx.signatures.resize(0);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(9, blob.size()); // 5 bytes + 2 * 2 bytes vins + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Two txin_gen, signatures vector contains only one empty element
  tx.signatures.resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, signatures vector contains two empty elements
  tx.signatures.resize(2);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_EQ(9, blob.size()); // 5 bytes + 2 * 2 bytes vins + 0 bytes extra + 0 bytes signatures
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Two txin_gen, signatures vector contains three empty elements
  tx.signatures.resize(3);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Two txin_gen, signatures vector contains two non empty elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(1);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // A few bytes instead of signature
  tx.vin.clear();
  tx.vin.push_back(txin_gen1);
  tx.signatures.clear();
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  blob.append(std::string(sizeof(crypto::signature) / 2, 'x'));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // blob contains one signature
  blob.append(std::string(sizeof(crypto::signature) / 2, 'y'));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Not enough signature vectors for all inputs
  txin_to_key txin_to_key1;
  txin_to_key1.amount = 1;
  memset(&txin_to_key1.k_image, 0x42, sizeof(crypto::key_image));
  txin_to_key1.key_offsets.push_back(12);
  txin_to_key1.key_offsets.push_back(3453);
  tx.vin.clear();
  tx.vin.push_back(txin_to_key1);
  tx.vin.push_back(txin_to_key1);
  tx.signatures.resize(1);
  tx.signatures[0].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // Too much signatures for two inputs
  tx.signatures.resize(3);
  tx.signatures[0].resize(2);
  tx.signatures[1].resize(2);
  tx.signatures[2].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // First signatures vector contains too little elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(1);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // First signatures vector contains too much elements
  tx.signatures.resize(2);
  tx.signatures[0].resize(3);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_FALSE(serialization::dump_binary(tx, blob));

  // There are signatures for each input
  tx.signatures.resize(2);
  tx.signatures[0].resize(2);
  tx.signatures[1].resize(2);
  tx.invalidate_hashes();
  ASSERT_TRUE(serialization::dump_binary(tx, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, tx1));
  ASSERT_EQ(tx, tx1);
  ASSERT_EQ(linearize_vector2(tx.signatures), linearize_vector2(tx1.signatures));

  // Blob doesn't contain enough data
  blob.resize(blob.size() - sizeof(crypto::signature) / 2);
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Blob contains too much data
  blob.resize(blob.size() + sizeof(crypto::signature));
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));

  // Blob contains one excess signature
  blob.resize(blob.size() + sizeof(crypto::signature) / 2);
  ASSERT_FALSE(serialization::parse_binary(blob, tx1));
}

TEST(Serialization, tx_types_conversion)
{
  std::string txp_blob_str = "070102000be7b6ad03dbfd70ec5ea3302c93e203cd29b00cc207da0dee030d41254d5d858ce92eadceee72f4334f55855c2ea79feb138d86971a744dfe2a020002f78eaec1483bfdf3762740f037561099168be033384282c8a61a2de398d6f15f0002e450ef16d307aedfad0e64586cb2bfa7ba16af0fe3a530dbc73aec26cf07983f2c0106dbd3fb6c300c7e48e20e9e252b1887f30c5fd439ec63fdb5ac941ef610000b020901b025547473133b9b00020000000008d095d10e009bcef3c5f4eb73d674ae643432735f187708c90835e19cdb23a5cdb32558758fbdf05107d199dc9a6d88553d0933ad9f6114ee0b643fa2257acc93de049e6abf6adb20406d50b7b644e78048614d00ca01ddd60830a240b05bde7982f52a31bad5c52930ba2e9222d699d073c641c8c598b4a404d2a33b753a9c5e66ce107f100b09bfce59cbf2dfd150174b08d2903a98a7863342659646464fb7c3ec7f7ef8b487705791955b2514054f393b770341e86ad1817810a9570e30f1b60f3d4f82e108efbd3e5d2e2bc3cdd2bc847da48f7dcaff756464d7364cd804f1b4bfecc5ef86641a9dcf25aa2e7d238de7540f290fb49b98932efea846c1e91cbabe4074f8e234bd40f72f82443acd1eb1f5b3e30a074e9525dec388148dce3b05721214208539249f6b88d6d1c4f75df86b4931395664a24fe70979b6cb999913f5ecc237c58f05a740e6181838a992ef8c8cf27f6f2fed1f83bee73c82da5a00f7f871d39d5844f60c6763b1977f4d534cdc086c82ceb43a38fdecf2be0a68287dc2c0ac9b0cdf33b5ef8bcaedb39aa7d5b7c6cab608a065bc90187ea3161fd66f7f32ba3dc982c6c0d230d86b3725146aeff8531c9ccdc62c2715dfa1b1bad39e30dc65a71579aa96557e43d0d9ba44277c22404e9351c7418de701af11e64b35f9ced5dcd640a298fd80e382ce2b1df64e36f4ce07b0273299c7cd178a3f95ae71d5aed29f213665cce6568f0b291f9b20d331cb1811f857ed730853e6c00a7a43b709651aa4921dbe09b40753ee8e884d1f592bf0edf53fff55600adb025cc8f3aa7c768fcdd65384b306d96e02c7ad9519fb0640872d6049345e9c0730eb256ea86ca1a2ca7f2cb388007d69c065f9e84477c80a6f3870bbbd77d05af6dad2a9adc32140c44b46cd0d4ddd006810808595889a2664f8bb900bb0d9c0cc1805b99ee3e93bd502d234720bbd6d93a4b8fc69c770d73defc69ce2ef4d08b1d4520dc2185070829880dca56ecb59002b572733fbe335d9fd53e209bdce37ea0b66c5f97cdb14181909bf011a0f1de6b8fcf07e033d010bcffcb23a84892d2ccd1013f849b37380f98a9962531b3f0adf2b3dd41f2900a49cb49d42140c443d25042f1b79546aecc8202b72a8455344c441667ec59902ec8bc4c866bb4ba682d408cf12c9483f54c4f91b90e29bb435d29616da06130d3ce5d2378781a43906f5032486a8ccfabeb54a7decb26953c24a68fd9bf21307f40fe3c83f71a0c1036181071f7c2be73aacf49a857958b3e7a2a3913b1e230c3571a8c147619c7caac597cd41d185476a4d12d3beeaf8beec292e77e2ed7609eea6af0bd9bb60235c620a7f273addc7aa69e62e0125d7a2f31697487934d80e49e53aa0078b4a172c55557adb49f194a4e5264f0dcad1d8084d8047504c0109ee619393d339e158cccb40806cd05e28543eea6fd0958871c7f353d4166ce007b63a358198fa1928d871e8b0ae552e48047f6622505c6697fce9398e9c80f4018c4523b413d681b392733ead1feba18a2588708e0655b2bee86c83b7fcc3940235a6a321a6ae7b2dcfb25ad361635b63ad7688d73514c148a65fe2e644ee1a09f3fa9c6d68976300bf2b8faa485b0e33940c7ef6bbd81d7361f9b718a2bb8c062287dd538c3bb790379d6189a4f04e6b8bf8dda9d536e66952ecf79ff7b39a0ada710ef03f0b653d77d202d84a2c8b5e60cf000103eb2709e2512503e46fe0f75fa1e8bd5bf31e9b57d8bb35680d063875152bc29493cb063fc6a5197ee66d0e";
  // Get the binary value for the TX hash
  std::string tx_hash_str = "2f797eeb6eb5a2fc2c953bc4d6acf4feac0c7b1bd678d5021bec656907e8fbf8";
  crypto::hash tx_hash;
  ASSERT_TRUE(epee::string_tools::hex_to_pod(tx_hash_str, tx_hash));
  
  // Try to parse the blob which we know is a valid TX prefix
  std::string txp_blob;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(txp_blob_str, txp_blob));
  cryptonote::transaction tx;
  tx.set_null();
  ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(txp_blob, tx));

  // Check that the hash matches
  ASSERT_EQ(get_transaction_hash(tx), tx_hash);
  /*
  // Verify we can serialize back into the original, should it be needed
  std::ostringstream s;
  binary_archive<true> a(s);
  ::serialization::serialize(a, const_cast<cryptonote::transaction&>(tx));
  std::string txp_calc_str = epee::string_tools::buff_to_hex_nodelimer(s.str());  
  ASSERT_EQ(txp_blob_str, txp_calc_str);
  */

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Conversion TX - testing offshore and onshore inputs/outputs
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
  std::string tx_blob_conversion_str = "070502000b9ebcee0395a233edc702d751a91574d31aea0e8b0289029f06e7ae34a859a988bbb20789ab182e863e04855b63753990c6e70f48d0c2deef8c04000bd5ecdc03cecc0adb97139ad32ae304ba073fe5018f0aec02d902c9da40ac69cea6118b41a9cfbbb9c72ea1f613d08269722c27aeab36e5459ff102000baa9aec03a1d630989a06e652918601c301f407981a852aa00de40250834d6bc552d0f76d1975346022d1e4e6d2af397b8f31e2e29a1c90abe42d3202000bbb9af703fa992bbfc101e1329d64ca0c9417ad03cd069d0192053c70c42964a1f25652149d3937babcef48a7071d6d3e2c01527cbf00cd5233bc02000ba8e3e803aebc1eaafa1bd578bc75ba13b50faa06c609ca03b8030d0ad111093fdec8b60580dc79bc661e0e97b894a576859a073ebe8f9185aa62060002e2166c38f5f7a07bfe22a1e101464d08b4a67519785f244d03af8f3db23c18bf000355bc56c5eb53334dc408bbcd5defde21d54497ec06e0d273eb36e973f41c18fc00036f8663673cab978a9a7a4de16b349badfbae017c5be226ce3746c8c58811d5d30002b84bf58a8628bbc5496cfa5cd2d8043c012c348f81076ea9d7a299b48db6d4b40002d51d2680485d591e416dd92415ceea9f9a2ccd8c38fb263762473529df3241e900025d9c80969a4930ead9ff07bc496437ff29a391c87a7c568d47b2b1a80289489e2101dee5ecb03c40a127afe2981f0d0ee6835cc27219758be3a915cb018550793779d1fb4e06e2f14f0000e2f14f00e2f14fd0efe8de9f8c0980b08dceb0b30d02030408b0d0acb7019ec4caadbb11bf7b22179044ee06c1c8aa7d34f9287389cc345e35e6ff93829672e18892b0c130d290500b1491a3df1d9d13e9a6dfead1b6760dfd1dda9baa94a9f1bffe3dad78385c73b5b0a6f0d933de09c3d5045ba6c400c782586e5723aa70e8d9c44e5730bcf2534267159f1edfc0a6033a5947a6a1f5483fea5bcac579ea119d24b9162680ff02448eba855d4cbce85ff10abf04456b26a42ac7bd0a4df920829c5c0adecc0dbcd075cd0297cd6bb1e395d81b6c3e43d6efbc22b258fd4ea1a7f8c49cb91227b3ac8f749b8f071d847a2ee423fa7a77be0e27f7097f53892460f0e5231e62762079f0360eaf4795e57306d22bc775ec22c59bbb1cbe392a691321667f7e027d2e78b21343cd61c1abdb251b0ab5a859dc7b3459cc7b2fae1fc5f66daa858a3abdd9909f4f1d56f98114db9702827ac26b8fb9818a49f87e466d8d0a3b38b84fa0dbd4d95159a12bb85310da03010373585f31c5b3691aece79b1f6205aa53b392dcdc660b0d21d8351aa604e295c825fbfff40acbb173889e83209cb0b2e8357545a03f7b92f63adf65d7b774146f441492d07f30adc8703fc4e6e81fdbb2489b125b3b875e960bf022f49a39536a9e6210a3e5cb04a45b112b1dd00cb2e5972b29ec0ca3b8adf804f2726462df981e4a5950eefbc929a49b080a53c927cc29d7b01f4303200a4c6497c71dd00a789323a700769a639ee1ae9fb144d55d98315912b9d5cffc3e9a78d7728d3b01099181593bc586776355aeecc33a2046e615c494b3b0d1b36f800d67de57560b5bc9e71f37065524320785eaeeacbbc75da91232f0fc906409236ea662650c19c2eec559d5a614bb5c49226757ea8a0344ff56bc2b6588db7e7a92301f7c1e109de14fb9b0918b9c9305a5e4a10b68fef3acb964c59bf5047b3627424cdbbffa04959461cc228a7db2c41074bee0888619a2aa4258012736dc54f8465e6e95131e428cdcadf4f7f932f045c5ad2b81b660066d73f4538849c208baadec3779dbce7ae0a67b2c3a383bb2d351f1da881d284ea787f7647a20cfa3eb0129cccc5db3f68272fd819bb0236687d76d3a0f16bf1dd91eaaa495dbb0b9a25c3b5739274eb0d7777ba0df6f12dc07743f97574d4ba31e397602f3c1179ac58582ad4133da094829328ade2d45ed9bde279b708b5bea85a9d128a0152dcad1f58e7e75a787c3c5ba03b3f1fe2d711a424efd235f82e1dfc78e8f912c3aae872c023368f4dcea6e61ddab16ccec3c0435c4e47a3e88f52e40ac39a165de09803d2a95c831303dd90c2333a61ca4f775011f468d7c9c3fbe18e3d8112bdc6bf84c8d72548b8765e5fb78332ff5825a71d11f8a514794be174e33a678b895a03d53adfe8c9c859c73ef21a69682205c044af9d3d5a4af77bebcb7f190b22c52b2d24d9a4f471274fdbb64672bf27ceada4256f775e983158c978462b0aea90908f44d0cd780bc096d5760c9e30277377180f1ee9056ca721cc1a60fc295dfb2d578c123c6ac0d4f13706deea04408a8c03fe657cbce7f21057c148d2484f47bb857fe7ad7f244458a376b4685ced412d6058d34dbff461c8b46b26de5eb4f8c60c7d27a57c8d8003c41769c8b5ce7a84ac0ef341b434824527b74bc0ab04b35f38663d4829193024203c2d4cc7b2413a6b076b9da0c51667a25d42879222e900abdffe445a94e022468b469c1d47347e5142caee0ef9ed19be33209f3efd3e4d93ec1ad811cea012d2708387f447757fb5f2654744d387620b7a2701aae0df1c86e00824b00760c3e5bebcbe26cc38afa3570ac31e19619c9b7d368cbe6713204bc963dad2cfc0722be40fe852061185f7e4865092533594d8c56fe467d70603dd0370443e18f05236ace6ccfeeacf29c068e939b3ac32f37dd9e73c3118be54ab12d3f7ef9440e20fdec3ca0412b04fc96384f4d62444fab9e9269d8a55bd1bca7acb9dfac880d908ea8902875bb7ab015144c3b1896f1c45bb65bca436d31feb2b2091cbbcf01fc1374cf7a0698f739f4f4d2a7d5090c7bc6e7678853dd6c871476f9d65e6d009de3a54da2709f9f0bc7c1e8d491f52da8d028d5e6063c51c997d1c13937e2045096abde9dcfbf2937929cbff9d226c16255d968e19934fe68f40751c5ea600b15c829e9290470a2b08250035b3374c44e679f8e34b3dfa24d0d37b87f48d40b692881700f6474b2d0266fcac0d0dc89a1cb7b55ab7b4603b7e5a912aecba30723d7c15d57ccc67e8d0cc08ed115f0d339cbe3e1b34159da9f5893b9e50157a229064452ae8366b9d0ecec4bd62dee7554808f692c4b30c5f2ef32e4dd26f50d4ddce8592b9b2243cd949efa23332bce9ce4b648c783bab76a82b990585975053e1d7a399303d39f650cf39eb7a7d3cbd87b5fed7fe23e7df3c0dbea0785570b8fe8b81aeef3997cc90ccf4d4f9015557f85e1b822088d345c759678f04cab0f7059660db547bfc37e06e2ecc9214bf9577983701616512d8d6156e6ef1c150249ba103985689e40da2cb0bb3d87dd9721e342d90cf63dac4844b304f5cae9093c5e778c04baec0ef20061ff65920e4f49e9a7dbd38f41a50da8d47d75b3d4016350a5bf63d4ccfb5b278af8734b5acef4d61630096db8d62fd579162485d50f8a710180b224ef552da9f751b196dc9401d4702ce7fdb3f94a90d13fc939100d153eedcffb4c543af899084f9e7666846ccd5a2234acada143262547897eb2098057155b23e9ddc7cb1e90b12d8fc64b5d372f17785a168c32fd64d182dd8c059392f0a61f89c21e3d9ca6503721db9cdda3cadefba2570fe132142506b3320c2605e57fe1f1d3ddf8c7fe8c8b4e52d203e57e173c61610e04cee294ecd6319d655582a1ab8f45b9aaa4bbd5b74341ed5ae15f7e3248b212af0b3cd8643ae802778750721f8fd082929691e436241f614e271bc33e780dc40118aaf8a8e19c03b7c4c04c1303ffcd7aaebdb1a7cac58803329772881c4448040dc21fd1ecaf09df088d6bbdd0e599b930715ee39fd58c57aeb29924ce920949af6edc4ce2800ae5a0b93bb3898f80635aea05f7a920d1ba83950365373643b80227163785f10db3826161d72a07234f673ae56a2ca94bfe96bba038c953af9b3f7ac3288188097a932295632492f9bf96236b83c9e25e87dc682cd1127410067863277b947d036b04283e0c64aed5f77fb0939e40667f1c6514d13ab449644e7cb3bf68c716024820ee508751f6209486041afb30fbecb97dda8cb373b701017dc12c5d38a5099b7ea265b1ff74c05228f76d5bfbaf54995b4997fb75161fa186cb0a38fada028acb5e3767417d2c31f0320cfb42e5235ef57914d8e89188333cba1fc88f11031e9315804f70c5e547e39ad45a7aabbba847d72eaba8bfdd04769119a8be6e0712f2ae54addce39b084d4a92ada97728639d8b9860414ee59853e282f4130fc9a9f73601569aa4124d934febc50c61b7cd5741e931ecb44e4ec7b17a8b126102c81871616c023e5608f5c1f0502bf1dd3adbcca18f1829f554a4a410ef2aa50adab6eb139e9661061093b9780eed068c406e7101310e779ecb18809885dece04dd7d580ab191528e95a46cf4d7885f66edb1fc5d56ba33313b15abec6339c7085a64d9cf5e5e71871bc561c400d8a6ee8c158495ce6abc8c22159b1bdd75fa05d1b6f44a8e2df70bb34e002a0187a369d2855e4442fa771903bb096fad65b508357c2568d7f3c4669f02cf60ea164bf95fa1118843ce862fb9ddd1eebb9ff70121a29ba35f709c20423d0e2db9a9d81cc527072ac18b89f5585e2b14c25de006b352f8efa67e55851a0dc393c688b63cab78328fc4777cb568c00ebd80d6a802fbf5cbac8b4d8d24ab53570a0ba67f1d2f7a43d62c881b8f80e5ac37caacd30950746b989c5e671cdfc2fc5bc1dfca3f3378dcda83eeb600959bb0efc2344a067c2857525169ac97d3c11e1c6729f4d0f9cd9fa55a925a13a7644de042aeda07ecd91dfc0646b7c260c188e41cd12bfb06bf149bf363c0f0c7a0568ef25086d546d318e6a13dc542cb06bce4e16e7f9fa06ed1eff68599490cb4544935707704b26e7463983174b4d9a7b620150013b609a50f77d6f119771a45b8e4f9e28f02011587691285613a86d93fe9307b27cb469e29ae9e20e5d8bc0675cbe88294077b34e15100d677a6e5c5aa2ebe944e705d368c91a141ddbbefb84be70ad95c00a500673c74218188b861df2c28cab15cfcb69a7f53b3e27adb14858ce3ca5b0527babaca8b0aa223d091efab6c4337d28fc7749ec9331515cd52967ae63bd60709b7e2da29035b471ae685e99fc0bcbe8414a31b907eb4c0dc3f3a5824627c0c806d9733ff3e44c41d64b640aadd41e8ef0aa1f7a982a71ce2973cc78682c00bbda3683d4055154b859f4b8ff9ac81e898dd162395486574ea9801ada296630ff484ca1c0ab72e6455d0499493cdc0625047a17feed7fc48f93b35afc555d80a2b4681cf84c285667182b771fabf14b51a6fe9c62116cc55d2dfe89086bc0406d6de8f7cd30c9a0ddd34a8860ad80fbc322cb30a78bfc4c6e455be15bb9b3608da034068d81b0b1c386479098a6b6bca00e92c9ab3586e33c6966dd268c49a979f29af76c8558841acd608b433324c0fc34d9d90d9391bed693afa606bbad640979ce66383b96125355746a90cd586c4f03b1aec2bc5768559ad151dc91c426ac00b412ab4941b118a8e0bb6bb1b4ac4c9171bc252d891aedd99d3f37a00a33a11344f7d895ca55931f9cd9c06b55e24efb60b045beef0f2a8806b1135679fcf03c74cde0141e1154cfc674d3d66e1e9725c196c5b01fbb7ce9c3be51a3ee999";

  // Get the binary value for the TX hash
  std::string tx_hash_conv_str = "93fcfd490373ee61863266ff1273b2d2c7c40bc0cea66934ac08de46818c72ea";
  crypto::hash tx_hash_conv;
  ASSERT_TRUE(epee::string_tools::hex_to_pod(tx_hash_conv_str, tx_hash_conv));
  
  // Try to parse the blob which we know is a valid TX
  std::string tx_blob_conversion;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(tx_blob_conversion_str, tx_blob_conversion));
  cryptonote::transaction tx_conv;
  tx_conv.set_null();
  ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(tx_blob_conversion, tx_conv));

  // Check that the hash matches
  ASSERT_EQ(get_transaction_hash(tx_conv), tx_hash_conv);

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Miner TX - testing pruned TXs and txin_gen inputs
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  std::string tx_blob_miner_str = "0701ff90ad4f04fc9acd95be5102ad9c8062227e855bda558022e150855c59553039c1a59ef339a5fd3f0bf51ef4f0b3b2f9a40402cf133862d242503ff9f1adafa126b7fe87c41cbd1acbaa9671461a6e173826cef49ecd0d035d2153eceb9d823aba8387c07e0eec42dfd4b1d6c03a9c87bb2a141a6575ffc7bcd25b0370ca2e2cbee56f1b1c1bc2e0b03ded2373ea81fa1b39ef549d4babfec79590fa5501fe43f00a609ae781aada077f224958e3211c1bcf1b8b6d95730229f133ab1099021100000018311d4c00000000000000000000014e8cd41796c89dc83b64795b733933e62941aa91b784e3b7270dc1b4074e579c0004ccad4fccad4fccad4fccad4f000000";

  std::string tx_hash_miner_str = "837a6f66e2d9c332cd08f47ce98e6a8e76446236a54c5c6b11db0ac181585fb7";
  crypto::hash tx_hash_miner;
  ASSERT_TRUE(epee::string_tools::hex_to_pod(tx_hash_miner_str, tx_hash_miner));
  
  // Try to parse the blob which we know is a valid TX
  std::string tx_blob_miner;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(tx_blob_miner_str, tx_blob_miner));
  cryptonote::transaction tx_miner;
  tx_miner.set_null();
  ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(tx_blob_miner, tx_miner));

  // Check that the hash matches
  ASSERT_EQ(get_transaction_hash(tx_miner), tx_hash_miner);

  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Genesis TX
  ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  std::string tx_blob_genesis_str = "023c01ff0001ffffffffffff07020bf6522f9152fa26cd1fc5c022b1a9e13dab697f3acf4b4d0ca6950a867a194321011d92826d0656958865a035264725799f39f6988faa97d532f972895de849496d00";
  std::string tx_blob_genesis;
  ASSERT_TRUE(epee::string_tools::parse_hexstr_to_binbuff(tx_blob_genesis_str, tx_blob_genesis));
  cryptonote::transaction tx_genesis;
  tx_genesis.set_null();
  ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(tx_blob_genesis, tx_genesis));
}

TEST(Serialization, serializes_ringct_types)
{
  string blob;
  rct::key key0, key1;
  rct::keyV keyv0, keyv1;
  rct::keyM keym0, keym1;
  rct::ctkey ctkey0, ctkey1;
  rct::ctkeyV ctkeyv0, ctkeyv1;
  rct::ctkeyM ctkeym0, ctkeym1;
  rct::ecdhTuple ecdh0, ecdh1;
  rct::boroSig boro0, boro1;
  rct::mgSig mg0, mg1;
  rct::clsag clsag0, clsag1;
  rct::Bulletproof bp0, bp1;
  rct::rctSig s0, s1;
  cryptonote::transaction tx0, tx1;

  key0 = rct::skGen();
  ASSERT_TRUE(serialization::dump_binary(key0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, key1));
  ASSERT_TRUE(key0 == key1);

  keyv0 = rct::skvGen(30);
  for (size_t n = 0; n < keyv0.size(); ++n)
    keyv0[n] = rct::skGen();
  ASSERT_TRUE(serialization::dump_binary(keyv0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, keyv1));
  ASSERT_TRUE(keyv0.size() == keyv1.size());
  for (size_t n = 0; n < keyv0.size(); ++n)
  {
    ASSERT_TRUE(keyv0[n] == keyv1[n]);
  }

  keym0 = rct::keyMInit(9, 12);
  for (size_t n = 0; n < keym0.size(); ++n)
    for (size_t i = 0; i < keym0[n].size(); ++i)
      keym0[n][i] = rct::skGen();
  ASSERT_TRUE(serialization::dump_binary(keym0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, keym1));
  ASSERT_TRUE(keym0.size() == keym1.size());
  for (size_t n = 0; n < keym0.size(); ++n)
  {
    ASSERT_TRUE(keym0[n].size() == keym1[n].size());
    for (size_t i = 0; i < keym0[n].size(); ++i)
    {
      ASSERT_TRUE(keym0[n][i] == keym1[n][i]);
    }
  }

  rct::skpkGen(ctkey0.dest, ctkey0.mask);
  ASSERT_TRUE(serialization::dump_binary(ctkey0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, ctkey1));
  ASSERT_TRUE(!memcmp(&ctkey0, &ctkey1, sizeof(ctkey0)));

  ctkeyv0 = std::vector<rct::ctkey>(14);
  for (size_t n = 0; n < ctkeyv0.size(); ++n)
    rct::skpkGen(ctkeyv0[n].dest, ctkeyv0[n].mask);
  ASSERT_TRUE(serialization::dump_binary(ctkeyv0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, ctkeyv1));
  ASSERT_TRUE(ctkeyv0.size() == ctkeyv1.size());
  for (size_t n = 0; n < ctkeyv0.size(); ++n)
  {
    ASSERT_TRUE(!memcmp(&ctkeyv0[n], &ctkeyv1[n], sizeof(ctkeyv0[n])));
  }

  ctkeym0 = std::vector<rct::ctkeyV>(9);
  for (size_t n = 0; n < ctkeym0.size(); ++n)
  {
    ctkeym0[n] = std::vector<rct::ctkey>(11);
    for (size_t i = 0; i < ctkeym0[n].size(); ++i)
      rct::skpkGen(ctkeym0[n][i].dest, ctkeym0[n][i].mask);
  }
  ASSERT_TRUE(serialization::dump_binary(ctkeym0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, ctkeym1));
  ASSERT_TRUE(ctkeym0.size() == ctkeym1.size());
  for (size_t n = 0; n < ctkeym0.size(); ++n)
  {
    ASSERT_TRUE(ctkeym0[n].size() == ctkeym1[n].size());
    for (size_t i = 0; i < ctkeym0.size(); ++i)
    {
      ASSERT_TRUE(!memcmp(&ctkeym0[n][i], &ctkeym1[n][i], sizeof(ctkeym0[n][i])));
    }
  }

  ecdh0.mask = rct::skGen();
  ecdh0.amount = rct::skGen();
  ASSERT_TRUE(serialization::dump_binary(ecdh0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, ecdh1));
  ASSERT_TRUE(!memcmp(&ecdh0.mask, &ecdh1.mask, sizeof(ecdh0.mask)));
  ASSERT_TRUE(!memcmp(&ecdh0.amount, &ecdh1.amount, sizeof(ecdh0.amount)));

  for (size_t n = 0; n < 64; ++n)
  {
    boro0.s0[n] = rct::skGen();
    boro0.s1[n] = rct::skGen();
  }
  boro0.ee = rct::skGen();
  ASSERT_TRUE(serialization::dump_binary(boro0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, boro1));
  ASSERT_TRUE(!memcmp(&boro0, &boro1, sizeof(boro0)));

  // create a full rct signature to use its innards
  vector<uint64_t> inamounts;
  rct::ctkeyV sc, pc;
  rct::ctkey sctmp, pctmp;
  inamounts.push_back(6000);
  tie(sctmp, pctmp) = rct::ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  inamounts.push_back(7000);
  tie(sctmp, pctmp) = rct::ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  vector<uint64_t> amounts;
  rct::keyV amount_keys;
  //add output 500
  amounts.push_back(500);
  amount_keys.push_back(rct::hash_to_scalar(rct::zero()));
  rct::keyV destinations;
  rct::key Sk, Pk;
  rct::skpkGen(Sk, Pk);
  destinations.push_back(Pk);
  //add output for 12500
  amounts.push_back(12500);
  amount_keys.push_back(rct::hash_to_scalar(rct::zero()));
  rct::skpkGen(Sk, Pk);
  destinations.push_back(Pk);
  //compute rct data with mixin 3
  const rct::RCTConfig rct_config{ rct::RangeProofPaddedBulletproof, 2 };
  s0 = rct::genRctSimple(rct::zero(), sc, pc, destinations, inamounts, amounts, amount_keys, 0, 3, rct_config, hw::get_device("default"));

  ASSERT_FALSE(s0.p.MGs.empty());
  ASSERT_TRUE(s0.p.CLSAGs.empty());
  mg0 = s0.p.MGs[0];
  ASSERT_TRUE(serialization::dump_binary(mg0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, mg1));
  ASSERT_TRUE(mg0.ss.size() == mg1.ss.size());
  for (size_t n = 0; n < mg0.ss.size(); ++n)
  {
    ASSERT_TRUE(mg0.ss[n] == mg1.ss[n]);
  }
  ASSERT_TRUE(mg0.cc == mg1.cc);

  // mixRing and II are not serialized, they are meant to be reconstructed
  ASSERT_TRUE(mg1.II.empty());

  ASSERT_FALSE(s0.p.bulletproofs.empty());
  bp0 = s0.p.bulletproofs.front();
  ASSERT_TRUE(serialization::dump_binary(bp0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, bp1));
  bp1.V = bp0.V; // this is not saved, as it is reconstructed from other tx data
  ASSERT_EQ(bp0, bp1);

  const rct::RCTConfig rct_config_clsag{ rct::RangeProofPaddedBulletproof, 3 };
  s0 = rct::genRctSimple(rct::zero(), sc, pc, destinations, inamounts, amounts, amount_keys, 0, 3, rct_config_clsag, hw::get_device("default"));

  ASSERT_FALSE(s0.p.CLSAGs.empty());
  ASSERT_TRUE(s0.p.MGs.empty());
  clsag0 = s0.p.CLSAGs[0];
  ASSERT_TRUE(serialization::dump_binary(clsag0, blob));
  ASSERT_TRUE(serialization::parse_binary(blob, clsag1));
  ASSERT_TRUE(clsag0.s.size() == clsag1.s.size());
  for (size_t n = 0; n < clsag0.s.size(); ++n)
  {
    ASSERT_TRUE(clsag0.s[n] == clsag1.s[n]);
  }
  ASSERT_TRUE(clsag0.c1 == clsag1.c1);
  // I is not serialized, they are meant to be reconstructed
  ASSERT_TRUE(clsag0.D == clsag1.D);
}

TEST(Serialization, portability_wallet)
{
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  tools::wallet2 w(nettype);
  const boost::filesystem::path wallet_file = unit_test::data_dir / "wallet_9svHk1";
  string password = "test";
  bool r = false;
  try
  {
    w.load(wallet_file.string(), password);
    r = true;
  }
  catch (const exception& e)
  {}
  ASSERT_TRUE(r);
  /*
  fields of tools::wallet2 to be checked: 
    std::vector<crypto::hash>                                       m_blockchain
    std::vector<transfer_details>                                   m_transfers               // TODO
    cryptonote::account_public_address                              m_account_public_address
    std::unordered_map<crypto::key_image, size_t>                   m_key_images
    std::unordered_map<crypto::hash, unconfirmed_transfer_details>  m_unconfirmed_txs
    std::unordered_multimap<crypto::hash, payment_details>          m_payments
    std::unordered_map<crypto::hash, crypto::secret_key>            m_tx_keys
    std::unordered_map<crypto::hash, confirmed_transfer_details>    m_confirmed_txs
    std::unordered_map<crypto::hash, std::string>                   m_tx_notes
    std::unordered_map<crypto::hash, payment_details>               m_unconfirmed_payments
    std::unordered_map<crypto::public_key, size_t>                  m_pub_keys
    std::vector<tools::wallet2::address_book_row>                   m_address_book
  */
  // blockchain
  ASSERT_TRUE(w.m_blockchain.size() == 1);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_blockchain[0]) == "48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b");
  // transfers (TODO)
  ASSERT_TRUE(w.m_transfers.size() == 3);
  // account public address
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_account_public_address.m_view_public_key) == "e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(w.m_account_public_address.m_spend_public_key) == "13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060");
  // key images
  ASSERT_TRUE(w.m_key_images.size() == 3);
  {
    crypto::key_image ki[3];
    epee::string_tools::hex_to_pod("c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8", ki[0]);
    epee::string_tools::hex_to_pod("d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0", ki[1]);
    epee::string_tools::hex_to_pod("6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76", ki[2]);
    ASSERT_EQ_MAP(0, w.m_key_images, ki[0]);
    ASSERT_EQ_MAP(1, w.m_key_images, ki[1]);
    ASSERT_EQ_MAP(2, w.m_key_images, ki[2]);
  }
  // unconfirmed txs
  ASSERT_TRUE(w.m_unconfirmed_txs.size() == 0);
  // payments
  ASSERT_TRUE(w.m_payments.size() == 2);
  {
    auto pd0 = w.m_payments.begin();
    auto pd1 = pd0;
    ++pd1;
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd0->first) == "0000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd1->first) == "0000000000000000000000000000000000000000000000000000000000000000");
    if (epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc")
      swap(pd0, pd1);
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd0->second.m_tx_hash) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(pd1->second.m_tx_hash) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
    ASSERT_TRUE(pd0->second.m_amount == 13400845012231);
    ASSERT_TRUE(pd1->second.m_amount == 1200000000000);
    ASSERT_TRUE(pd0->second.m_block_height == 818424);
    ASSERT_TRUE(pd1->second.m_block_height == 818522);
    ASSERT_TRUE(pd0->second.m_unlock_time == 818484);
    ASSERT_TRUE(pd1->second.m_unlock_time == 0);
    ASSERT_TRUE(pd0->second.m_timestamp == 1483263366);
    ASSERT_TRUE(pd1->second.m_timestamp == 1483272963);
  }
  // tx keys
  ASSERT_TRUE(w.m_tx_keys.size() == 2);
  {
    const std::vector<std::pair<std::string, std::string>> txid_txkey =
    {
      {"b9aac8c020ab33859e0c0b6331f46a8780d349e7ac17b067116e2d87bf48daad", "bf3614c6de1d06c09add5d92a5265d8c76af706f7bc6ac830d6b0d109aa87701"},
      {"6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", "e556884246df5a787def6732c6ea38f1e092fa13e5ea98f732b99c07a6332003"},
    };
    for (size_t i = 0; i < txid_txkey.size(); ++i)
    {
      crypto::hash txid;
      crypto::secret_key txkey;
      epee::string_tools::hex_to_pod(txid_txkey[i].first, txid);
      epee::string_tools::hex_to_pod(txid_txkey[i].second, txkey);
      ASSERT_EQ_MAP(txkey, w.m_tx_keys, txid);
    }
  }
  // confirmed txs
  ASSERT_TRUE(w.m_confirmed_txs.size() == 1);
  // tx notes
  ASSERT_TRUE(w.m_tx_notes.size() == 2);
  {
    crypto::hash h[2];
    epee::string_tools::hex_to_pod("15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e", h[0]);
    epee::string_tools::hex_to_pod("6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba", h[1]);
    ASSERT_EQ_MAP("sample note", w.m_tx_notes, h[0]);
    ASSERT_EQ_MAP("sample note 2", w.m_tx_notes, h[1]);
  }
  // unconfirmed payments
  ASSERT_TRUE(w.m_unconfirmed_payments.size() == 0);
  // pub keys
  ASSERT_TRUE(w.m_pub_keys.size() == 3);
  {
    crypto::public_key pubkey[3];
    epee::string_tools::hex_to_pod("33f75f264574cb3a9ea5b24220a5312e183d36dc321c9091dfbb720922a4f7b0", pubkey[0]);
    epee::string_tools::hex_to_pod("5066ff2ce9861b1d131cf16eeaa01264933a49f28242b97b153e922ec7b4b3cb", pubkey[1]);
    epee::string_tools::hex_to_pod("0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8", pubkey[2]);
    ASSERT_EQ_MAP(0, w.m_pub_keys, pubkey[0]);
    ASSERT_EQ_MAP(1, w.m_pub_keys, pubkey[1]);
    ASSERT_EQ_MAP(2, w.m_pub_keys, pubkey[2]);
  }
  // address book
  ASSERT_TRUE(w.m_address_book.size() == 1);
  {
    auto address_book_row = w.m_address_book.begin();
    ASSERT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_spend_public_key) == "9bc53a6ff7b0831c9470f71b6b972dbe5ad1e8606f72682868b1dda64e119fb3");
    ASSERT_TRUE(epee::string_tools::pod_to_hex(address_book_row->m_address.m_view_public_key) == "49fece1ef97dc0c0f7a5e2106e75e96edd910f7e86b56e1e308cd0cf734df191");
    ASSERT_TRUE(address_book_row->m_description == "testnet wallet 9y52S6");
  }
}

#define OUTPUT_EXPORT_FILE_MAGIC "Monero output export\003"
TEST(Serialization, portability_outputs)
{
  // read file
  const boost::filesystem::path filename = unit_test::data_dir / "outputs";
  std::string data;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), data);
  ASSERT_TRUE(r);
  const size_t magiclen = strlen(OUTPUT_EXPORT_FILE_MAGIC);
  ASSERT_FALSE(data.size() < magiclen || memcmp(data.data(), OUTPUT_EXPORT_FILE_MAGIC, magiclen));
  // decrypt (copied from wallet2::decrypt)
  auto decrypt = [] (const std::string &ciphertext, const crypto::secret_key &skey, bool authenticated) -> string
  {
    const size_t prefix_size = sizeof(chacha_iv) + (authenticated ? sizeof(crypto::signature) : 0);
    if(ciphertext.size() < prefix_size)
      return {};
    crypto::chacha_key key;
    crypto::generate_chacha_key(&skey, sizeof(skey), key, 1);
    const crypto::chacha_iv &iv = *(const crypto::chacha_iv*)&ciphertext[0];
    std::string plaintext;
    plaintext.resize(ciphertext.size() - prefix_size);
    if (authenticated)
    {
      crypto::hash hash;
      crypto::cn_fast_hash(ciphertext.data(), ciphertext.size() - sizeof(signature), hash);
      crypto::public_key pkey;
      crypto::secret_key_to_public_key(skey, pkey);
      const crypto::signature &signature = *(const crypto::signature*)&ciphertext[ciphertext.size() - sizeof(crypto::signature)];
      if(!crypto::check_signature(hash, pkey, signature))
        return {};
    }
    crypto::chacha8(ciphertext.data() + sizeof(iv), ciphertext.size() - prefix_size, key, iv, &plaintext[0]);
    return plaintext;
  };
  crypto::secret_key view_secret_key;
  epee::string_tools::hex_to_pod("339673bb1187e2f73ba7841ab6841c5553f96e9f13f8fe6612e69318db4e9d0a", view_secret_key);
  bool authenticated = true;
  data = decrypt(std::string(data, magiclen), view_secret_key, authenticated);
  ASSERT_FALSE(data.empty());
  // check public view/spend keys
  const size_t headerlen = 2 * sizeof(crypto::public_key);
  ASSERT_FALSE(data.size() < headerlen);
  const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
  const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];
  ASSERT_TRUE(epee::string_tools::pod_to_hex(public_spend_key) == "13daa2af00ad26a372d317195de0bdd716f7a05d33bc4d7aff1664b6ee93c060");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(public_view_key) == "e47d4b6df6ab7339539148c2a03ad3e2f3434e5ab2046848e1f21369a3937cad");
  r = false;
  std::vector<tools::wallet2::transfer_details> outputs;
  try
  {
    std::istringstream iss(std::string(data, headerlen));
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> outputs;
    r = true;
  }
  catch (...)
  {}
  ASSERT_TRUE(r);
  /*
  fields of tools::wallet2::transfer_details to be checked: 
    uint64_t                        m_block_height
    cryptonote::transaction_prefix  m_tx                        // TODO
    crypto::hash                    m_txid
    size_t                          m_internal_output_index
    uint64_t                        m_global_output_index
    bool                            m_spent
    uint64_t                        m_spent_height
    crypto::key_image               m_key_image
    rct::key                        m_mask
    uint64_t                        m_amount
    bool                            m_rct
    bool                            m_key_image_known
    size_t                          m_pk_index
  */
  ASSERT_TRUE(outputs.size() == 3);
  auto& td0 = outputs[0];
  auto& td1 = outputs[1];
  auto& td2 = outputs[2];
  ASSERT_TRUE(td0.m_block_height == 818424);
  ASSERT_TRUE(td1.m_block_height == 818522);
  ASSERT_TRUE(td2.m_block_height == 818522);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_txid) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_txid) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_txid) == "6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba");
  ASSERT_TRUE(td0.m_internal_output_index == 0);
  ASSERT_TRUE(td1.m_internal_output_index == 0);
  ASSERT_TRUE(td2.m_internal_output_index == 1);
  ASSERT_TRUE(td0.m_global_output_index == 19642);
  ASSERT_TRUE(td1.m_global_output_index == 19757);
  ASSERT_TRUE(td2.m_global_output_index == 19760);
  ASSERT_TRUE (td0.m_spent);
  ASSERT_FALSE(td1.m_spent);
  ASSERT_FALSE(td2.m_spent);
  ASSERT_TRUE(td0.m_spent_height == 0);
  ASSERT_TRUE(td1.m_spent_height == 0);
  ASSERT_TRUE(td2.m_spent_height == 0);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_key_image) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_key_image) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_key_image) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_mask) == "0100000000000000000000000000000000000000000000000000000000000000");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_mask) == "d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  ASSERT_TRUE(td0.m_amount == 13400845012231);
  ASSERT_TRUE(td1.m_amount == 1200000000000);
  ASSERT_TRUE(td2.m_amount == 11066009260865);
  ASSERT_TRUE(td0.m_rct);
  ASSERT_TRUE(td1.m_rct);
  ASSERT_TRUE(td2.m_rct);
  ASSERT_TRUE(td0.m_key_image_known);
  ASSERT_TRUE(td1.m_key_image_known);
  ASSERT_TRUE(td2.m_key_image_known);
  ASSERT_TRUE(td0.m_pk_index == 0);
  ASSERT_TRUE(td1.m_pk_index == 0);
  ASSERT_TRUE(td2.m_pk_index == 0);
}

struct unsigned_tx_set
{
  std::vector<tools::wallet2::tx_construction_data> txes;
  tools::wallet2::transfer_container transfers;
};
template <class Archive>
inline void serialize(Archive &a, unsigned_tx_set &x, const boost::serialization::version_type ver)
{
  a & x.txes;
  a & x.transfers;
}
#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\003"
TEST(Serialization, portability_unsigned_tx)
{
  const boost::filesystem::path filename = unit_test::data_dir / "unsigned_monero_tx";
  std::string s;
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), s);
  ASSERT_TRUE(r);
  const size_t magiclen = strlen(UNSIGNED_TX_PREFIX);
  ASSERT_FALSE(strncmp(s.c_str(), UNSIGNED_TX_PREFIX, magiclen));
  unsigned_tx_set exported_txs;
  s = s.substr(magiclen);
  r = false;
  try
  {
    std::istringstream iss(s);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> exported_txs;
    r = true;
  }
  catch (...)  
  {}
  ASSERT_TRUE(r);
  /*
  fields of tools::wallet2::unsigned_tx_set to be checked:
    std::vector<tx_construction_data> txes
    std::vector<wallet2::transfer_details> m_transfers

  fields of toolw::wallet2::tx_construction_data to be checked:
    std::vector<cryptonote::tx_source_entry>      sources
    cryptonote::tx_destination_entry              change_dts
    std::vector<cryptonote::tx_destination_entry> splitted_dsts
    std::list<size_t>                             selected_transfers
    std::vector<uint8_t>                          extra
    uint64_t                                      unlock_time
    bool                                          use_rct
    std::vector<cryptonote::tx_destination_entry> dests
  
  fields of cryptonote::tx_source_entry to be checked:
    std::vector<std::pair<uint64_t, rct::ctkey>>  outputs
    size_t                                        real_output
    crypto::public_key                            real_out_tx_key
    size_t                                        real_output_in_tx_index
    uint64_t                                      amount
    bool                                          rct
    rct::key                                      mask
  
  fields of cryptonote::tx_destination_entry to be checked:
    uint64_t                amount
    account_public_address  addr
  */
  // txes
  ASSERT_TRUE(exported_txs.txes.size() == 1);
  auto& tcd = exported_txs.txes[0];
  // tcd.sources
  ASSERT_TRUE(tcd.sources.size() == 1);
  auto& tse = tcd.sources[0];
  // tcd.sources[0].outputs
  ASSERT_TRUE(tse.outputs.size() == 5);
  auto& out0 = tse.outputs[0];
  auto& out1 = tse.outputs[1];
  auto& out2 = tse.outputs[2];
  auto& out3 = tse.outputs[3];
  auto& out4 = tse.outputs[4];
  ASSERT_TRUE(out0.first == 6295);
  ASSERT_TRUE(out1.first == 14302);
  ASSERT_TRUE(out2.first == 17598);
  ASSERT_TRUE(out3.first == 18671);
  ASSERT_TRUE(out4.first == 19760);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out0.second) == "e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out1.second) == "c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out2.second) == "176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out3.second) == "ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out4.second) == "0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04");
  // tcd.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
  ASSERT_TRUE(tse.real_output == 4);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.real_out_tx_key) == "4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05");
  ASSERT_TRUE(tse.real_output_in_tx_index == 1); 
  ASSERT_TRUE(tse.amount == 11066009260865);
  ASSERT_TRUE(tse.rct);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  // tcd.change_dts
  ASSERT_TRUE(tcd.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, tcd.change_dts.addr) == "9svHk1wHPo3ULf2AZykghzcye6sitaRE4MaDjPC6uanTHCynHjJHZaiAb922PojE1GexhhRt1LVf5DC43feyrRZMLXQr3mk");
  // tcd.splitted_dsts
  ASSERT_TRUE(tcd.splitted_dsts.size() == 2);
  auto& splitted_dst0 = tcd.splitted_dsts[0];
  auto& splitted_dst1 = tcd.splitted_dsts[1];
  ASSERT_TRUE(splitted_dst0.amount == 1400000000000);
  ASSERT_TRUE(splitted_dst1.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst0.addr) == "9xnhrMczQkPeoGi6dyu6BgKAYX4tZsDs6KHCkyTStDBKL4M4pM1gfCR3utmTAcSaKHGa1R5o266FbdnubErmij3oMdLyYgA");
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst1.addr) == "9svHk1wHPo3ULf2AZykghzcye6sitaRE4MaDjPC6uanTHCynHjJHZaiAb922PojE1GexhhRt1LVf5DC43feyrRZMLXQr3mk");
  // tcd.selected_transfers
  ASSERT_TRUE(tcd.selected_transfers.size() == 1);
  ASSERT_TRUE(tcd.selected_transfers.front() == 2);
  // tcd.extra
  ASSERT_TRUE(tcd.extra.size() == 68);
  // tcd.{unlock_time, use_rct}
  ASSERT_TRUE(tcd.unlock_time == 0);
  ASSERT_TRUE(tcd.use_rct);
  // tcd.dests
  ASSERT_TRUE(tcd.dests.size() == 1);
  auto& dest = tcd.dests[0];
  ASSERT_TRUE(dest.amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, dest.addr) == "9xnhrMczQkPeoGi6dyu6BgKAYX4tZsDs6KHCkyTStDBKL4M4pM1gfCR3utmTAcSaKHGa1R5o266FbdnubErmij3oMdLyYgA");
  // transfers
  ASSERT_TRUE(exported_txs.transfers.size() == 3);
  auto& td0 = exported_txs.transfers[0];
  auto& td1 = exported_txs.transfers[1];
  auto& td2 = exported_txs.transfers[2];
  ASSERT_TRUE(td0.m_block_height == 818424);
  ASSERT_TRUE(td1.m_block_height == 818522);
  ASSERT_TRUE(td2.m_block_height == 818522);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_txid) == "15024343b38e77a1a9860dfed29921fa17e833fec837191a6b04fa7cb9605b8e");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_txid) == "ec34c9bb12b99af33d49691384eee5bed9171498ff04e59516505f35d1fc5efc");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_txid) == "6e7013684d35820f66c6679197ded9329bfe0e495effa47e7b25258799858dba");
  ASSERT_TRUE(td0.m_internal_output_index == 0);
  ASSERT_TRUE(td1.m_internal_output_index == 0);
  ASSERT_TRUE(td2.m_internal_output_index == 1);
  ASSERT_TRUE(td0.m_global_output_index == 19642);
  ASSERT_TRUE(td1.m_global_output_index == 19757);
  ASSERT_TRUE(td2.m_global_output_index == 19760);
  ASSERT_TRUE (td0.m_spent);
  ASSERT_FALSE(td1.m_spent);
  ASSERT_FALSE(td2.m_spent);
  ASSERT_TRUE(td0.m_spent_height == 0);
  ASSERT_TRUE(td1.m_spent_height == 0);
  ASSERT_TRUE(td2.m_spent_height == 0);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_key_image) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_key_image) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_key_image) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td0.m_mask) == "0100000000000000000000000000000000000000000000000000000000000000");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td1.m_mask) == "d3997a7b27fa199a377643b88cbd3f20f447496746dabe92d288730ecaeda007");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(td2.m_mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  ASSERT_TRUE(td0.m_amount == 13400845012231);
  ASSERT_TRUE(td1.m_amount == 1200000000000);
  ASSERT_TRUE(td2.m_amount == 11066009260865);
  ASSERT_TRUE(td0.m_rct);
  ASSERT_TRUE(td1.m_rct);
  ASSERT_TRUE(td2.m_rct);
  ASSERT_TRUE(td0.m_key_image_known);
  ASSERT_TRUE(td1.m_key_image_known);
  ASSERT_TRUE(td2.m_key_image_known);
  ASSERT_TRUE(td0.m_pk_index == 0);
  ASSERT_TRUE(td1.m_pk_index == 0);
  ASSERT_TRUE(td2.m_pk_index == 0);
}

#define SIGNED_TX_PREFIX "Monero signed tx set\003"
TEST(Serialization, portability_signed_tx)
{
  const boost::filesystem::path filename = unit_test::data_dir / "signed_monero_tx";
  const cryptonote::network_type nettype = cryptonote::TESTNET;
  std::string s;
  bool r = epee::file_io_utils::load_file_to_string(filename.string(), s);
  ASSERT_TRUE(r);
  const size_t magiclen = strlen(SIGNED_TX_PREFIX);
  ASSERT_FALSE(strncmp(s.c_str(), SIGNED_TX_PREFIX, magiclen));
  tools::wallet2::signed_tx_set exported_txs;
  s = s.substr(magiclen);
  r = false;
  try
  {
    std::istringstream iss(s);
    boost::archive::portable_binary_iarchive ar(iss);
    ar >> exported_txs;
    r = true;
  }
  catch (...)
  {}
  ASSERT_TRUE(r);
  /*
  fields of tools::wallet2::signed_tx_set to be checked:
    std::vector<pending_tx>         ptx
    std::vector<crypto::key_image>  key_images
  
  fields of tools::walllet2::pending_tx to be checked:
    cryptonote::transaction                       tx                  // TODO
    uint64_t                                      dust
    uint64_t                                      fee
    bool                                          dust_added_to_fee
    cryptonote::tx_destination_entry              change_dts
    std::list<size_t>                             selected_transfers
    std::string                                   key_images
    crypto::secret_key                            tx_key
    std::vector<cryptonote::tx_destination_entry> dests
    tx_construction_data                          construction_data
  */
  // ptx
  ASSERT_TRUE(exported_txs.ptx.size() == 1);
  auto& ptx = exported_txs.ptx[0];
  // ptx.{dust, fee, dust_added_to_fee}
  ASSERT_TRUE (ptx.dust == 0);
  ASSERT_TRUE (ptx.fee == 34800487462);
  ASSERT_FALSE(ptx.dust_added_to_fee);
  // ptx.change.{amount, addr}
  ASSERT_TRUE(ptx.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, ptx.change_dts.addr) == "9svHk1wHPo3ULf2AZykghzcye6sitaRE4MaDjPC6uanTHCynHjJHZaiAb922PojE1GexhhRt1LVf5DC43feyrRZMLXQr3mk");
  // ptx.selected_transfers
  ASSERT_TRUE(ptx.selected_transfers.size() == 1);
  ASSERT_TRUE(ptx.selected_transfers.front() == 2);
  // ptx.{key_images, tx_key}
  ASSERT_TRUE(ptx.key_images == "<6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76> ");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ptx.tx_key) == "0100000000000000000000000000000000000000000000000000000000000000");
  // ptx.dests
  ASSERT_TRUE(ptx.dests.size() == 1);
  ASSERT_TRUE(ptx.dests[0].amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, ptx.dests[0].addr) == "9xnhrMczQkPeoGi6dyu6BgKAYX4tZsDs6KHCkyTStDBKL4M4pM1gfCR3utmTAcSaKHGa1R5o266FbdnubErmij3oMdLyYgA");
  // ptx.construction_data
  auto& tcd = ptx.construction_data;
  ASSERT_TRUE(tcd.sources.size() == 1);
  auto& tse = tcd.sources[0];
  // ptx.construction_data.sources[0].outputs
  ASSERT_TRUE(tse.outputs.size() == 5);
  auto& out0 = tse.outputs[0];
  auto& out1 = tse.outputs[1];
  auto& out2 = tse.outputs[2];
  auto& out3 = tse.outputs[3];
  auto& out4 = tse.outputs[4];
  ASSERT_TRUE(out0.first == 6295);
  ASSERT_TRUE(out1.first == 14302);
  ASSERT_TRUE(out2.first == 17598);
  ASSERT_TRUE(out3.first == 18671);
  ASSERT_TRUE(out4.first == 19760);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out0.second) == "e7272cb589954ddeedd20de9411ed57265f154d41f33cec9ff69e5d642e09814096490b0ac85308342acf436cc0270d53abef9dc04c6202f2459e879bfd40ce6");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out1.second) == "c3a9f49d1fe75939cc3feb39871ce0a7366c2879a63faa1a5cf34e65723b120a272ff0c7d84ab8b6ee3528d196450b0e28b3fed276bc2597a2b5b17afb9354ab");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out2.second) == "176e239c8c39000c2275e2f63ed7d55c55e0843524091522bbd3d3b869044969021fad70fc1244115449d4754829ae7c47346342ee5d52a2cdd47dfc351d0ab0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out3.second) == "ef12d7946302fb064f2ba9df1a73d72233ac74664ed3b370580fa3bdc377542ad93f64898bd95851d6efe0d7bf2dbbea9b7c6b3c57e2c807e7b17d55b4622259");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(out4.second) == "0d8467e16e73d16510452b78823e082e05ee3a63788d40de577cf31eb555f0c8525096cbc88d00a841eed66f3cdb6f0a018e6ce9fb9433ed61afba15cbbebd04");
  // ptx.construction_data.sources[0].{real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask}
  ASSERT_TRUE(tse.real_output == 4);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.real_out_tx_key) == "4d86c7ba1c285fe4bc1cd7b54ba894fa89fa02fc6b0bbeea67d53251acd14a05");
  ASSERT_TRUE(tse.real_output_in_tx_index == 1); 
  ASSERT_TRUE(tse.amount == 11066009260865);
  ASSERT_TRUE(tse.rct);
  ASSERT_TRUE(epee::string_tools::pod_to_hex(tse.mask) == "789bafff169ef206aa21219342c69ca52ce1d78d776c10b21d14bdd960fc7703");
  // ptx.construction_data.change_dts
  ASSERT_TRUE(tcd.change_dts.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, tcd.change_dts.addr) == "9svHk1wHPo3ULf2AZykghzcye6sitaRE4MaDjPC6uanTHCynHjJHZaiAb922PojE1GexhhRt1LVf5DC43feyrRZMLXQr3mk");
  // ptx.construction_data.splitted_dsts
  ASSERT_TRUE(tcd.splitted_dsts.size() == 2);
  auto& splitted_dst0 = tcd.splitted_dsts[0];
  auto& splitted_dst1 = tcd.splitted_dsts[1];
  ASSERT_TRUE(splitted_dst0.amount == 1400000000000);
  ASSERT_TRUE(splitted_dst1.amount == 9631208773403);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst0.addr) == "9xnhrMczQkPeoGi6dyu6BgKAYX4tZsDs6KHCkyTStDBKL4M4pM1gfCR3utmTAcSaKHGa1R5o266FbdnubErmij3oMdLyYgA");
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, splitted_dst1.addr) == "9svHk1wHPo3ULf2AZykghzcye6sitaRE4MaDjPC6uanTHCynHjJHZaiAb922PojE1GexhhRt1LVf5DC43feyrRZMLXQr3mk");
  // ptx.construction_data.selected_transfers
  ASSERT_TRUE(tcd.selected_transfers.size() == 1);
  ASSERT_TRUE(tcd.selected_transfers.front() == 2);
  // ptx.construction_data.extra
  ASSERT_TRUE(tcd.extra.size() == 68);
  // ptx.construction_data.{unlock_time, use_rct}
  ASSERT_TRUE(tcd.unlock_time == 0);
  ASSERT_TRUE(tcd.use_rct);
  // ptx.construction_data.dests
  ASSERT_TRUE(tcd.dests.size() == 1);
  auto& dest = tcd.dests[0];
  ASSERT_TRUE(dest.amount == 1400000000000);
  ASSERT_TRUE(cryptonote::get_account_address_as_str(nettype, false, dest.addr) == "9xnhrMczQkPeoGi6dyu6BgKAYX4tZsDs6KHCkyTStDBKL4M4pM1gfCR3utmTAcSaKHGa1R5o266FbdnubErmij3oMdLyYgA");
  // key_images
  ASSERT_TRUE(exported_txs.key_images.size() == 3);
  auto& ki0 = exported_txs.key_images[0];
  auto& ki1 = exported_txs.key_images[1];
  auto& ki2 = exported_txs.key_images[2];
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki0) == "c5680d3735b90871ca5e3d90cd82d6483eed1151b9ab75c2c8c3a7d89e00a5a8");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki1) == "d54cbd435a8d636ad9b01b8d4f3eb13bd0cf1ce98eddf53ab1617f9b763e66c0");
  ASSERT_TRUE(epee::string_tools::pod_to_hex(ki2) == "6c3cd6af97c4070a7aef9b1344e7463e29c7cd245076fdb65da447a34da3ca76");
}

TEST(Serialization, difficulty_type)
{
  std::vector<cryptonote::difficulty_type> v_original;

  for(int i = 0; i != 100; i++)
  {
    v_original.push_back(cryptonote::difficulty_type("117868131154734361989189100"));
    if(v_original.size() > 1)
      v_original.back() *= v_original[v_original.size()-2];
  }

  std::stringstream ss;
  boost::archive::portable_binary_oarchive a(ss);
  a << v_original;

  std::vector<cryptonote::difficulty_type> v_unserialized;

  boost::archive::portable_binary_iarchive a2(ss);
  a2 >> v_unserialized;

  ASSERT_EQ(v_original, v_unserialized);
}
