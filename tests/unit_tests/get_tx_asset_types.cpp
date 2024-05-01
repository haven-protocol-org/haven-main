// Copyright (c) 2019-2021, Haven Protocol
// Portions copyright (c) 2016-2019, The Monero Project
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
#include "cryptonote_core/cryptonote_tx_utils.cpp"
#include "cryptonote_basic/cryptonote_basic.h"
#include "vector"


// Regular transfers tests. Same asset type in input and output. Should be successful.
TEST(get_tx_asset_types, successful_on_1_input_type_1_output_type_XHV)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_to_key xhv_key;
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_to_key out_xhv;
    out.target = out_xhv;
    out1.target = out_xhv;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XHV");
    EXPECT_EQ(dest, "XHV");
}
TEST(get_tx_asset_types, successful_on_1_input_type_1_output_type_XUSD)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_offshore offshore_key;
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_offshore out_xusd;
    out.target = out_xusd;
    out1.target = out_xusd;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XUSD");
    EXPECT_EQ(dest, "XUSD");
}
TEST(get_tx_asset_types, successful_on_1_input_type_1_output_type_XASSET)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XBTC";
    out_xasset1.asset_type = "XBTC";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XBTC");
    EXPECT_EQ(dest, "XBTC");
}

// pass on correct conversions
TEST(get_tx_asset_types, successful_offshore)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XHV");
    EXPECT_EQ(dest, "XUSD");
}
TEST(get_tx_asset_types, successful_onshore)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_onshore xusd_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    
    tx.vin.push_back(xusd_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);
    cryptonote::tx_out out2;
    out2.target = out_xhv;

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XUSD");
    EXPECT_EQ(dest, "XHV");
}
TEST(get_tx_asset_types, successful_xusd_to_xasset)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;

    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XGBP";
    cryptonote::txout_offshore out_offshore;
    
    tx.vin.push_back(offshore_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_offshore;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XUSD");
    EXPECT_EQ(dest, "XGBP");
}
TEST(get_tx_asset_types, successful_xasset_to_xusd)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XEUR";

    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XEUR";
    cryptonote::txout_offshore out_offshore;
    
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    out.target = out_offshore;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XEUR");
    EXPECT_EQ(dest, "XUSD");
}

// fail on multiple input types - 3 or more
TEST(get_tx_asset_types, fail_on_multiple_input_types_3_or_more)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - 1. XHV, 2. not XUSD
TEST(get_tx_asset_types, fail_on_multiple_input_types_XHV_not_XUSD)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - 1. XUSD, 2. not XHV
TEST(get_tx_asset_types, fail_on_multiple_input_types_XUSD_not_XHV)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(onshore_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - ins) 1. XHV 2. XUSD outs) only XHV 
TEST(get_tx_asset_types, fail_on_multiple_input_types_only_XHV_out)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - ins) 1. XHV 2. XUSD outs) only XUSD 
TEST(get_tx_asset_types, fail_on_multiple_input_types_only_XUSD_out)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - ins) 1. XHV 2. XUSD outs) 1. not XHV  2. not XUSD
TEST(get_tx_asset_types, fail_on_multiple_input_types_out_not_XHV_not_XUSD)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XEUR";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xasset;
    tx.vout.push_back(out);
    tx.vout.push_back(out);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - ins) 1. XHV 2. XUSD outs) 1. XHV  2. not XUSD
TEST(get_tx_asset_types, fail_on_multiple_input_types_out_XHV_not_XUSD)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XEUR";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on multiple input types - ins) 1. XHV 2. XUSD outs) 1. not XHV  2. XUSD
TEST(get_tx_asset_types, fail_on_multiple_input_types_out_XUSD_not_XHV)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XEUR";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xasset;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// pass on multiple input types - ins) 1. XHV 2. XUSD outs) 1. XHV  2. XUSD
TEST(get_tx_asset_types, pass_on_multiple_input_types_onshore)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_offshore offshore_key;
    cryptonote::txin_onshore onshore_key;
    cryptonote::txin_xasset xasset_key;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);
    tx.vin.push_back(offshore_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on single input types with more than 2 output types
TEST(get_tx_asset_types, fail_single_input_and_more_than_2output_types)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_offshore out_offshore;
    cryptonote::txout_xasset out_xasset;
    out_xasset.asset_type = "XAU";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_offshore;
    tx.vout.push_back(out1);
    cryptonote::tx_out out2;
    out2.target = out_xasset;
    tx.vout.push_back(out2);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on single input types & single output types & they are not equal
TEST(get_tx_asset_types, fail_single_input_single_output_types_are_not_equal)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XAG";
    out_xasset1.asset_type = "XAG";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    out.target = out_xasset;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset1;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on single input types & 2 output types & none of the outputs matches inputs
TEST(get_tx_asset_types, none_of_output_matches_input)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XAG";
    out_xasset1.asset_type = "XBTC";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    out.target = out_xasset;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset1;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// pass on single input types & 2 output types & 1 of the outputs matches inputs, other ddesn't but not allowed. xhv -> xasset
// This case will expected to be caught by get_tx_type()
TEST(get_tx_asset_types, successful_on_logical_input_output_but_not_allowed)
{
    cryptonote::transaction tx;
    tx.version = 7;
    cryptonote::txin_to_key xhv_key;

    cryptonote::txout_to_key out_xhv;
    cryptonote::txout_xasset out_xasset1;
    out_xasset1.asset_type = "XBTC";

    tx.vin.push_back(xhv_key);
    tx.vin.push_back(xhv_key);

    cryptonote::tx_out out;
    out.target = out_xhv;
    tx.vout.push_back(out);
    cryptonote::tx_out out1;
    out1.target = out_xasset1;
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XHV");
    EXPECT_EQ(dest, "XBTC");
}

// pass on 2 different xasset but source and dest are different. This case will expectedd to be catch by get_tx_type()
TEST(get_tx_asset_types, successful_on_logical_input_output_but_not_allowed_xassets)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XBTC";
    out_xasset1.asset_type = "XJPY";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_TRUE(get_tx_asset_types(tx, tx.hash, source, dest, false));

    EXPECT_EQ(source, "XBTC");
    EXPECT_EQ(dest, "XJPY");
}

// fail on 2 different xasset
TEST(get_tx_asset_types, fail_on_2_different_xasset)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XJPY";
    out_xasset1.asset_type = "XJPY";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on unknown asset types
TEST(get_tx_asset_types, fail_on_2_unknown_asset_types)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "xabc";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "xabc";
    out_xasset1.asset_type = "xabc";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on unknown asset types
TEST(get_tx_asset_types, fail_on_2_unknown_asset_types_and_multiple_outs)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "xabc";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "xabc";
    out_xasset1.asset_type = "xbdc";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}

// fail on unknown asset types
TEST(get_tx_asset_types, fail_on_1_unknown_asset_type)
{
    cryptonote::transaction tx;
    tx.version = 7;
    
    cryptonote::txin_xasset xasset_key;
    xasset_key.asset_type = "XBTC";
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);
    tx.vin.push_back(xasset_key);

    cryptonote::tx_out out;
    cryptonote::tx_out out1;
    cryptonote::txout_xasset out_xasset;
    cryptonote::txout_xasset out_xasset1;
    out_xasset.asset_type = "XBTC";
    out_xasset1.asset_type = "xbdc";
    out.target = out_xasset;
    out1.target = out_xasset1;

    tx.vout.push_back(out);
    tx.vout.push_back(out1);

    std::string source;
    std::string dest;
    EXPECT_FALSE(get_tx_asset_types(tx, tx.hash, source, dest, false));
}
