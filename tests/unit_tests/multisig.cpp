// Copyright (c) 2017-2019, The Monero Project
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

#include "gtest/gtest.h"

#include <cstdint>

#include "wallet/wallet2.h"

static const struct
{
  const char *address;
  const char *spendkey;
} test_addresses[] =
{
  {
    "hvtZwmWZgy1hS1UrSeNWQqJE9kkSkEPy4eKraNdQVfHHRd9GBEa7fmibikhXyjY5tbLqacbsWaNvcKMNbBMCf43Y4ZQi8FQMnC",
    "68dc98ce3a19ce74efc9bc75a0eb9ceb027fda989d47437d6fa2032cde922b02"
  },
  {
    "hvtZvzkhyEZHuMcpCjs3ZvcV7UgDXpsFpjoLmq5bPUtzF1gYPkvKjAhC6Y9LexQhPoj6nPCjTmKnLBoPuJjUsfbo1U1P2wvzJs",
    "4dbfb1623d06598e2c944ca71c1b71736512a2691c890d842e846c3496dd4600"
  },
  {
    "hvtaF3ripuYiVMbtRJhQDbisvYLSTrPGrBJPeMG57C4wD6hMfTheNqHRhxYfPBk7JoZzr7H7oQvLmccDuCESaX4E8MmsJHxe51",
    "15584507f9ec2fbea8a2e93e19fcf64c2d8387ccb6409f35f8ed35ead63f900d"
  },
  {
    "hvtaANv77yGW8G2XAp947qZ2zLsxzJ5b4Jn4KoQgYDg3AXWBey8eTwd5WnZeSWsqk9eqquQsPcdPNXAZBGCQSMPk1GRyK1jRnc",
    "87606cca17207e2d9bfc4053d593e3c85b1d1de472d61d8429402433f72f130d"
  },
  {
    "hvtaMXhnzf6Q1HS5TJAjNB7nVFZutn5rsgZ8JuXFAfCVLi6xpoRkAdT3MgSWvnddoPHM4P7zRRodr6kJFUXG16nk2bDkUene1G",
    "289d618afa98c84e03daf0735212fc626a5689edc64ad05da5fd45461b5fe80e"
  }
};

static const size_t KEYS_COUNT = 5;

static void make_wallet(unsigned int idx, tools::wallet2 &wallet)
{
  ASSERT_TRUE(idx < sizeof(test_addresses) / sizeof(test_addresses[0]));

  crypto::secret_key spendkey;
  epee::string_tools::hex_to_pod(test_addresses[idx].spendkey, spendkey);

  try
  {
    wallet.init("", boost::none, boost::asio::ip::tcp::endpoint{}, 0, true, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
    wallet.set_subaddress_lookahead(1, 1);
    wallet.generate("", "", spendkey, true, false);
    ASSERT_TRUE(test_addresses[idx].address == wallet.get_account().get_public_address_str(cryptonote::TESTNET));
    wallet.decrypt_keys("");
    ASSERT_TRUE(test_addresses[idx].spendkey == epee::string_tools::pod_to_hex(wallet.get_account().get_keys().m_spend_secret_key));
    wallet.encrypt_keys("");
  }
  catch (const std::exception &e)
  {
    MFATAL("Error creating test wallet: " << e.what());
    ASSERT_TRUE(0);
  }
}

static std::vector<std::string> exchange_round(std::vector<tools::wallet2>& wallets, const std::vector<std::string>& mis)
{
  std::vector<std::string> new_infos;
  for (size_t i = 0; i < wallets.size(); ++i) {
      new_infos.push_back(wallets[i].exchange_multisig_keys("", mis));
  }

  return new_infos;
}

static void make_wallets(std::vector<tools::wallet2>& wallets, unsigned int M)
{
  ASSERT_TRUE(wallets.size() > 1 && wallets.size() <= KEYS_COUNT);
  ASSERT_TRUE(M <= wallets.size());

  std::vector<std::string> mis(wallets.size());

  for (size_t i = 0; i < wallets.size(); ++i) {
    make_wallet(i, wallets[i]);

    wallets[i].decrypt_keys("");
    mis[i] = wallets[i].get_multisig_info();
    wallets[i].encrypt_keys("");
  }

  for (auto& wallet: wallets) {
    ASSERT_FALSE(wallet.multisig());
  }

  std::vector<std::string> mxis;
  for (size_t i = 0; i < wallets.size(); ++i) {
    // it's ok to put all of multisig keys in this function. it throws in case of error
    mxis.push_back(wallets[i].make_multisig("", mis, M));
  }

  while (!mxis[0].empty()) {
    mxis = exchange_round(wallets, mxis);
  }

  for (size_t i = 0; i < wallets.size(); ++i) {
    ASSERT_TRUE(mxis[i].empty());
    bool ready;
    uint32_t threshold, total;
    ASSERT_TRUE(wallets[i].multisig(&ready, &threshold, &total));
    ASSERT_TRUE(ready);
    ASSERT_TRUE(threshold == M);
    ASSERT_TRUE(total == wallets.size());

    if (i != 0) {
      // "equals" is transitive relation so we need only to compare first wallet's address to each others' addresses. no need to compare 0's address with itself.
      ASSERT_TRUE(wallets[0].get_account().get_public_address_str(cryptonote::TESTNET) == wallets[i].get_account().get_public_address_str(cryptonote::TESTNET));
    }
  }
}

TEST(multisig, make_2_2)
{
  std::vector<tools::wallet2> wallets(2);
  make_wallets(wallets, 2);
}

TEST(multisig, make_3_3)
{
  std::vector<tools::wallet2> wallets(3);
  make_wallets(wallets, 3);
}

TEST(multisig, make_2_3)
{
  std::vector<tools::wallet2> wallets(3);
  make_wallets(wallets, 2);
}

TEST(multisig, make_2_4)
{
  std::vector<tools::wallet2> wallets(4);
  make_wallets(wallets, 2);
}

TEST(multisig, make_2_5)
{
  std::vector<tools::wallet2> wallets(5);
  make_wallets(wallets, 2);
}
