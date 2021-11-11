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

#include <boost/filesystem.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <cstdio>
#include <iostream>
#include <chrono>
#include <thread>

#include "gtest/gtest.h"

#include "string_tools.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

using namespace cryptonote;
using epee::string_tools::pod_to_hex;

#define ASSERT_HASH_EQ(a,b) ASSERT_EQ(pod_to_hex(a), pod_to_hex(b))

namespace {  // anonymous namespace

const std::vector<std::string> t_blocks =
  {
    "1112f98e8d8a06ccb6a159c0090c6406fe6ff4f4beb24c7a58919de872e4afc2bd92c8b4ec76e4934366dc1072bd150a0000003019ea2100000000b011985c3e01000000623d01000000000000000000000000b0382187d7000000a0ffc2cddd05000080ecbedbc500000010891ae4a8000000b083ff90cd63000000000000000000000000000000000000007ccbaa07060000000a8713b005000000e994b896050000003854037a0500007a47436100000000ab7515042d819d26b231d34c0b206a5fe1c3535d75755eb2d4a8039c6c2d86a7e5c5d147abb86d684f8344f0df5b8e65adefc9703009b79af461305a66fb20bd048d0301ffd102068c899dda98cc0702cb12b7b8f38ec8578f3be760db24bd27bc31a624322c7f33f0faa38a242b3dc7ccf4e2b1953302b98d7448e393a76a7a7d1540f69019ed8b48510321d277eb85f1905b38117508e8d7f8d701055e072aa3593f96181dbf24ef91b9905406d5e67bb329be6c83258dd44ffe93fa0458455552f8e2ae0b055323636ef2043b9022a7dc2dc94bc77c73c572dd6b38196cf5521cdd71b80c750458455552f89385d601035a13992cce1c85859592f155e59919bdb34e47aa7607728baf41884d13c8bbe5a8faa10b0382404d1d959493b8681a8860d07ea8377b8e8dcf2361b21326c2832460a08003420196f8010e2a94a785bbada123a8a1b2a640e7086328abe825220d62aa99e95ef5015e72cafe75f63f92a943a4af8b3f615f907498fda108d4de9f20d4cd33b94534000000000003da4951a649772c7e91a8a7de483bd7b5620dc256ccefcd01bbe0d17682476ff1cef8bef9003bca69d76ca459955adaea68e10493f010f821802ee2eb92dafa5a7cf7438d3515e601d80a9aade0018b940175bfffa4f0663942dcd92fa2289475"
  , "1112fa8e8d8a064d094bcaadd998e85071bb15990e0e3b717f81fd62a1cf0db48e57300672469f22035df31072bd150a0000003019ea2100000000b011985c3e01000000623d01000000000000000000000000b0382187d7000000a0ffc2cddd05000080ecbedbc500000010891ae4a8000000b083ff90cd63000000000000000000000000000000000000007ccbaa07060000000a8713b005000000e994b896050000003854037a0500007b474361000000000fa62f524f77185e3977cfdc1a90940cd4807bba2f625ae3900a4c9091fef25f33d5e68c5ef9e4eaae73eb27451fc6a5810cab9e422eeed0c3c031817efca56e048e0301ffd20202e5cda69396cc070236d19353c9bbc84959e2be9034269e7f07af3bf6ae5c90a551253fd05c508e79859f96b0953302a13c0efb5a0b530b804609bd9c6d477149bb2ae80a04aa00e912c88ba8276f50420149e7c6154c92df5be8dd55598e5978ae5d0fa7e61733ff6575c11e3ead76e09e010b7a022e53d916db7ae4c9774b7707dfde5ec403b9ed0848e8fc6d45ddd9c2be000000000000"
  };

const std::vector<size_t> t_sizes =
  {
    5552
  , 159
  };

const std::vector<difficulty_type> t_diffs =
  {
    10
  , 10
  };

const std::vector<uint64_t> t_coins =
  {
    35161763646968
  , 35161696581226
  };

const std::vector<std::vector<std::string>> t_transactions =
  {
    {
      "04000202000b0fd901274712420917062459fe4e1dc1f5994636462c0402393da68d04c58a769072b7bfe1f75f84cd51153102000b1e6f0c8d011e73101109141cc248a4540f3199737f80f75a3175939e1e6762afdc8fa6dc68b1d6f4b953b01e020002e24079c073414888ee0d2835b41f2fd092d7878fb2ec86efbdfe72f16fbc42c200028c4aaa70ae0b5549e671a196903972c1c83b56f4d31859668e5f563bb15eaca02c01226a9ee2d91df9cac5561d54ad2b75d334ac8420f3c59dfddcc854a968130ae60209017e7696e0174389400000000006e0e1c5a8020000000000cddf5d253e44e5018e4f8c3116a6da9faa03a44ddd3aa7707e90da5b2c6b29799652007b1f5fd669a5d18e12351583c769ecd4c511fe261a41ba3cdf681aa05cb0e119be3e1964e0a4fdea9500a5bbc601000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000163790721a5cf23dcd7a3a3f9d473ac95e65046a8893aee481765c139e8299b288fba10b423b51ca0331d8b8b6c24be2908e1bfbdd97f0d70b1750a611a4d7ec69030665bcfa7d3b1a5c1868f38c154bff27f242708f18a2bbd18785c0b6cac163bca431dcedec0846f99f4bc259eb2dc9939e185dca9897151d8a770b0701351cebbbb56db9f8d77af3fa90a28e4a202e040d49a76f457d2e1c4dbef92478f06bc8efb3cc6ba310712a9b3eee2b5006a72f760882bc92d781ca2a78226ea040007cb92dc0815e9d7a26e15838b3beb257f6c0a04f5083e92394652eded42440c0917bf9414b651ad77902e7f0f73c7055f80b53746e8fadfcc9b5fb731036eec1abee49f442ea4bc3ba94bb8918d24a01810a76c812648848e6c160cd38b886bff5d15174853c9e45c8fbf7f329c700246bbc34afe4fcc13568031ffde90f1b9cf54b73f7dd0efb52caaa1864a7d1511c6664e034cd7d2f0104980be546e6901a7f3cd154174765211d8d3fdaf6027c7680516266e8c4b41ffa6efb33dc8ba12287fbe5d07cd4d0da7762613414f00b9156e0a048d93bf942661597c26fbe1555c0745878edefda90d28dcdec55117a5b3506cde3f39e0e82092738ae22af2eacfa50e30f21be9a8c8119109d60e7a05176972c1d2a851498949fdde066212b0679373fe8fb481ab290c3eddf6eb339cfa9631e5ce08c7934987221560c65fba3302a5ae2b2031636ab1a58fdaf5add0165075d68cf1fb29193a6bd6ce940aba6f34ed7a251752225c076634c102a7a4db0e5e164aa2f47ff495c32e123970dfee1a9ce69c54d563d37cde0dcfb632cbd2923a2d79c45c0946d54b063cc0c3e4e7bde3d5f65f345a5b9f7f702de03977048322a9b4d1a023c33e63524db11c5f164795a88cd1daa5eb264dedc1b7adcfc909f338a7858fdca15ff487269f1b547c017555c300dc424c7c3f60eaa7c416afd221ad9877d593ae494b2e73d27e09ec0be5a6157a88b4b3ec4caa9661eeb3a2005d4dbbb4ff1a7edec34fb84f9b26f003f1e16e589a5e3ec11260fd42f152fa67a6ee1b1502b0de6a5d6ef5d4d308230b9c1e20340034952905b8f02a7ffa083d28c5bf2e0a30d26706528f1d5b34af0b8b0522cba500d0e76c3dd5bba1ab0ffa58ee0c46f0d62c3e8333e5314154270a88669729a8a68958a84f9a612f290bffa90644fba42bbe65ba29288dbdddb40f2bae4f3cbd5a5579a996aaae20662acb0ac308f208abe0e28d9f0a872e08a909308d915fd4d1c256391490a42bb6d54e5b70b478931e1f1e23580e7570030c0c12819e57f3dfee34d4f6541a2210c729528adb304c1b83b7cd4792c14562ae0db420d0419ad87080f62c69c6d470a6e665eb93eabffb0cf2f82164c1e99b1e0fd2ae58c4d3c3faf01c512fa57a97cbc74ac265504ec87726cec92b5b099bcd04e673cf15a7f8fdf90a60b4172f94537141185ae0825bd3c9cbe626af0e036e015f5a0399cbceea6cb3b3a34c7a13a62e1964f179f9ffb97dcd139adb5d90b3074ba1650e7fddba3dc982d6067a4fc9380549406d478959e3fc0f4aa4052fee0c211fa5002bfb3cabefa3c20543d5643d9519409bc5db2ee183ca2d003abeda59ecfc244e2121ec70d3d2a04e4a62e1c6a41a36baaed71200b22432cced0ae706618e1d29a4175fb0b4753a7f21dfe8cc5b70e923377ad86f936c352557b2560f274c2e31114ba87dc17ad39fc3f1fee18ec6dd4fc03110e9c5901474bc810009c7a31ea4c8e4ea298f21ddd60221af62bea7239e358dfaceefe7a62563f5660d45eee7abcdd25b50ed8b0721cb10a12aac18ea899c93f1fb94a1ac9a5a28e60c50a09b6eac0fbbc7919696efe3cf7084039844d45717d88387d3a50d71ddb900701fdfa790e61518e248b65bff8e831b7184f4f3870536132fa27a01e2888b00b808a6aad350d8dabd9e5d783b62189360aa814627a422996637dc08a42f77071bef5a5981da1016404c194d456efecf53d68cfd62afe7633c8d26ccc319610fd3fa32a90e8e544137c339fd5a943bd0c4a858361a0a9d07252415eb30c409058f96577a980f1a9888f64924c821aaddd3c9cf24274ede6e9dcf3fdece83e8000d0bdd5f09d657c892f3c36d30c3d8393344ac41f7589dbe3d88d6e02ba4280404832385b7fdbd05526a7b592f16cc0a4ceae574914c9ab4cd0def838acb756473d10d588967ef89ea2a67b85635e75dee97ee79ae1906c35cf22605848068618225c41a6704ab9506d66df331bf1feab49a40908368ea6bee6b388532f94da2"
    , "040001050004584555520ba90402020202020203030201537695763936a906763f6f0290053895609d53851793114bf1558d3e5bc9fe120200054cf71cb7327b24d4f3d5738f3f315261a25a56c85dbdfdcc79a1fa3ecd8c592804584555520005a987239df8e6e93da2b4c3e46b9da14029809bc32bc111165861ca8bbf88d83104584555522c0190995901aac86581724316428cc868fbe76b5ac500150df490916088c8cbfdfc0209017d629f39f02a796f00000000060000e0baa7e301000000b1225ad7f551c6bd85228e045b722af501000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000005d1c42bc569eb4628c3705c09f94d5306ed2e63a42a11c7334445f90d869373fc90da366c0c213306479fc0ecec76c08e042eb5902d7241b00773b0acc5520da01e4b06b99de33bff43e56c862346671c640766379d3373391f0ee4319f2db4a2f697f2d7ebd4dd03a042a535a03de2f4a0035bd30ac86f5d179fec787204e4c43635e5860978e762c9114731d27162ce80df1461c68a7955d6e55ed9c376039fcdead2b09299ad8a9b57b5a9a7d7cbebab4ba1190c3560319605c0497e19f1b4feda80cee3333d9dabacf6a90df83e0840d45281f70e9a9f1829a7b9d430485063f66fd521439b5db1e18e76003d28b2518a9082777998595ca04f07288cefa06079fbc3f8885274680529a5359aecf8b280b4580ad41c9047c5028eb003c77e380133b2103cb64e18e471282831a5063921ec34bff0699329e4ef903833b95f418f76ae1038a406dd0a79a256312584e45b8da9e6d9387e8a7f8b1a066d53ffc7206a50b5fc09748005a269a62256b07e2096ab948a13227573c741610e61f75cd8353902b7dcd27e9ba20edc98648aa376643f7c6d17d49b60d13602647900323bf0bcc4cc34387afa466e43868fb455806b71388c96ff441f0c8eea540e25ac0ffcefd3385d64c8181a83bbcb02003c08d9ac7d0048090b9717d23aab83c23ad0715d45d36b5cb97bbbb5368d2b127ac3fa38a1d5ba78946b0bcad14074231e05d8f6e18347307998a094523e21d952f6462491187a152b4a083e183de55d1eb051cba17c749203c3817f664bc8f04caab6f9e2af875aa73532bd5dc1302da3b2e6aa1b788fd6627db70eda78e3d076f23d198ff6334aab96230c3e98ade029df25322cdc09e77569b72dfc79d24d6966a69108a6c0b1850dfa932a5041517c5b1661a8b8bda1114f2881416c83a83e6a5b506fd373b12b754b4477855a35a4d30fa3d0c38b7ab13f49be0ee153157d7f3257c8fbb9db5b3d7e9eb3e802647566e9714b3da06aa8b97a59107316603a1fa32258c5a519afb8f38bd0ad08a4da301ab6b7c215510f7498d8df5914f16fe76fdcf7ccab76a186ffdcf64a6517abe01d2cefee2e9cf0f8c63af0e356cc19f2c8bd9163bda5589b561a327bcae2cf40c8af7c8afd7d84368aa8fd3e9ba1847707ae0978fa0105bfedf509a5be6646c0fdc595b38c7c76ff81a0dd5904f20c7f0d8ab68ec73b497c8d9cc9e97399f6c06bc0959b9287b02c8ac90deff595cee973e7ecfe8d98a86152dcc8fb63efed10f7477927a9a75d3dc5c77c2abe53ebad0710067b74a7fc31fac6fc250e2d437055991539b6d6d6aa3b1f7dcd09f58b68403bd29f9252e3e6748ad50e77f6ff20e7f37657725eb9e891c1aefc0edee51da01f457ae8cb6a531a01a4c3661555706cd3f5b86379aa3601736c410ac699b75b0120af62e2d19d0c8175d4dc92e4302c38562c9d654d03db3f6d03edcb26401607d6b8e9f5a95d9dabe351c102734086b58086fe48c9976eac957206de9e01f2a4a50d16d12a4f5564ddf2e1335170d6fae84c40dd86a1fe6910c804caacd34ae164f92313d0ae0f10a0ee43d4f58007686d489a591b9f824a09edf2928dd8c4cc1f04fa2756dfb67818459755f3c0e407e48585fd137d196fbae5dc1f5fd6a99f0bbfe53a041a9dad47fb7207b0a0b2c44c2a5158edb2f011266469ff6cc76304c6121ab5212fd0818e18b79d7f27a57dbe490c675fdf77da2f4a80597740353097aa7c10b6f0e40b4c262b9699a7a"
    , "04000103000b9b010105050602fe0204060405f1e1020f668c9adec5645bc7f150ee007dc22e4fde84c2f1c1058dc9197703af02000375af3f835a49bdd71a39e3fa26a44872f965d0c314fe3bb2cd518e30887a763200030ca926de718ec1103b4536e065f830c640c1a3cbe319f20b8c1d4d84ea1250f32c01c03a62b530cc9a016244b6c6ae0603eb69d0693f829fa7ff28321e5ee1f68df4020901f3a3316bd72e7f0a000000000600a08ea7e1010000000059198b78ff75bd7638d0d608d2dc70d501000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000f17863b2fefd9a9e192fba1b8b7cdd8712bae24ed4bbdfcae4bee026ec020b721ffb44b82e866ebb9de943197beac60a59738251c4d35f843f62f496d3c666ab010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000176e0f650c0dec981b30f25ea4bd6b32b5f6733c90b38cc7d2d47bf3cb0a01be8f872cad629fae54d91186ca406ee0f656cf7ffc0ec53062a59176bea302c5c809fbd7f9e8ea337d81237cf3c47fd0af4a9e606e23d38952e57a6295425cdac791279a1fe0b15f7ff086574aaadcc3d4d0903f6df5265ab99be8408a535b7157f535f34590d742af480cbd41a7f75e657a6ded2dccfe22758b41dcc41c0634106b17ed9873e7c61ebbc9a39e1868ba4104b679ee49f6c89248d13d021b4467b03073357c004c4bcf1e6dc0a702416dc7a6c6c30423eeb3060b18fc283a7a4f2206944495a543f4fa8621f4b482357ea24dbf3c9ea86ef0445ead81a75ef0b2d530432c691b822e438bcb5d0a28d12628df00f8d11e5a487ea8d1d9cfb3ee19d1225999a4a7eeec4e8307987431d0da4ebb4504f7e2f811a7f367af0113c3e91139118d2e19fac74e81f9fe0ee7fc4b40d33441bc5f0646d99ccec4e899eb456fda6ab29d8b969c834256f626503b6c032d797a5b99be8a4377152df9b97a5ca268e783e1027b1175b011d57c263359467cada0b035ad1a4a54d6116c16eb8fd4ba407a8051adfd356f2294479c50d6df7719d1e54e5b52605a098231e2312f375d67da210cc93c25bc8dac5cd5a791a3a37ae336a756af02d547afdbcaec0ab26de8978bfccf44e61ef02365c76f2759bf00368aa54be60e41e020e9aa4b37802a60e9d0b4f42bf2216793dd0f0c390964f46eaaeff719e69ad148f93553b4bc1ed5daae7adea06a5973cf854e7a4582e69a91a471d6161382754d2d0ce25e33c99a0c858af0ee2c918fd2b4d8ab3bdb89c05e34f16466ffbe9915750b2f89244538218fea88306602472eef2397d46e0b052aa50718605a99a96327514e03958c8c234e396457bf28d17bf189d05d983a18689d26aa9afc1b126db0ebc4ef75ed50db45c05e49c8dc6887ef6498ee1a8f3e5124fb5446909e2e6261dfa5b6183b90b345449ff0c33ff4a5139b2aa5c92d5fa33e96abd79dea5a9403acd9df5899106d7bfe878bdbfe2afe0820ebf926e0e893bcf7a76741d6711d34cb914667a9f09340832801e74da878e59adf2cf446c93b8a22722874ca6446f8e46589332fb029ddc52240d9433f1ff64948a1c6fb572b34f45776fd5bb61bb4ea77e723e6d0eb4437c294bf3e66fc8fb48397e48a9545868a0f1e76ec8a4e7b88a9c7aee25043fe001a2fd74e4feee01471ca95a341f4e97e9e6ccd11ae923d320c9c0fcfc0026c7cc23a00a1f9e84620407b3142562189e31959cec0aebb31825d6e8917e0a257e15239eab11bf52c910c774a2b80a9c1b4053f0a230ae23140261a020150f12f65b61185a88def22cf2e69047963eacc4f623c013354ef8e0ad8aac44c7005daf7aab212551a249ca2636cb624fad6ec9d3da93ce8ac77b12a3a58591b20673f66204f25671fe8ad18cbd1dfa030b06f085831b722b903855f72027bc7001eaafe47bc8d8c7632a3c53eae5f74198650f2c17ac47acfce9e3bf4cd2d63e092b8640704ec0c38d997bb522b41327737d7613074cc5ab584f4f2313f11c260fff4aa040b94614ffc27d12ad1f7c9901b472f83e0f3754d646e311061c0fc39da1e580c74634815c2d8f465e6901995ff654e2b37bd5a4ef31b14d5748452423"
    }
  , {
    }
  };

// if the return type (blobdata for now) of block_to_blob ever changes
// from std::string, this might break.
bool compare_blocks(const block& a, const block& b)
{
  auto hash_a = pod_to_hex(get_block_hash(a));
  auto hash_b = pod_to_hex(get_block_hash(b));

  return hash_a == hash_b;
}

/*
void print_block(const block& blk, const std::string& prefix = "")
{
  std::cerr << prefix << ": " << std::endl
            << "\thash - " << pod_to_hex(get_block_hash(blk)) << std::endl
            << "\tparent - " << pod_to_hex(blk.prev_id) << std::endl
            << "\ttimestamp - " << blk.timestamp << std::endl
  ;
}

// if the return type (blobdata for now) of tx_to_blob ever changes
// from std::string, this might break.
bool compare_txs(const transaction& a, const transaction& b)
{
  auto ab = tx_to_blob(a);
  auto bb = tx_to_blob(b);

  return ab == bb;
}
*/

// convert hex string to string that has values based on that hex
// thankfully should automatically ignore null-terminator.
std::string h2b(const std::string& s)
{
  bool upper = true;
  std::string result;
  unsigned char val = 0;
  for (char c : s)
  {
    if (upper)
    {
      val = 0;
      if (c <= 'f' && c >= 'a')
      {
        val = ((c - 'a') + 10) << 4;
      }
      else
      {
        val = (c - '0') << 4;
      }
    }
    else
    {
      if (c <= 'f' && c >= 'a')
      {
        val |= (c - 'a') + 10;
      }
      else
      {
        val |= c - '0';
      }
      result += (char)val;
    }
    upper = !upper;
  }
  return result;
}

template <typename T>
class BlockchainDBTest : public testing::Test
{
protected:
  BlockchainDBTest() : m_db(new T()), m_hardfork(*m_db, 1, 0)
  {
    for (auto& i : t_blocks)
    {
      block bl;
      blobdata bd = h2b(i);
      CHECK_AND_ASSERT_THROW_MES(parse_and_validate_block_from_blob(bd, bl), "Invalid block");
      m_blocks.push_back(std::make_pair(bl, bd));
    }
    for (auto& i : t_transactions)
    {
      std::vector<std::pair<transaction, blobdata>> txs;
      for (auto& j : i)
      {
        transaction tx;
        blobdata bd = h2b(j);
        CHECK_AND_ASSERT_THROW_MES(parse_and_validate_tx_from_blob(bd, tx), "Invalid transaction");
        txs.push_back(std::make_pair(tx, bd));
      }
      m_txs.push_back(txs);
    }
  }

  ~BlockchainDBTest() {
    delete m_db;
    remove_files();
  }

  BlockchainDB* m_db;
  HardFork m_hardfork;
  std::string m_prefix;
  std::vector<std::pair<block, blobdata>> m_blocks;
  std::vector<std::vector<std::pair<transaction, blobdata>>> m_txs;
  std::vector<std::string> m_filenames;

  void init_hard_fork()
  {
    m_hardfork.init();
    m_db->set_hard_fork(&m_hardfork);
  }

  void get_filenames()
  {
    m_filenames = m_db->get_filenames();
    for (auto& f : m_filenames)
    {
      std::cerr << "File created by test: " << f << std::endl;
    }
  }

  void remove_files()
  {
    // remove each file the db created, making sure it starts with fname.
    for (auto& f : m_filenames)
    {
      if (boost::starts_with(f, m_prefix))
      {
        boost::filesystem::remove(f);
      }
      else
      {
        std::cerr << "File created by test not to be removed (for safety): " << f << std::endl;
      }
    }

    // remove directory if it still exists
    boost::filesystem::remove_all(m_prefix);
  }

  void set_prefix(const std::string& prefix)
  {
    m_prefix = prefix;
  }
};

using testing::Types;

typedef Types<BlockchainLMDB> implementations;

TYPED_TEST_CASE(BlockchainDBTest, implementations);

TYPED_TEST(BlockchainDBTest, OpenAndClose)
{
  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();

  // make sure open when already open DOES throw
  ASSERT_THROW(this->m_db->open(dirPath), DB_OPEN_FAILURE);

  ASSERT_NO_THROW(this->m_db->close());
}

TYPED_TEST(BlockchainDBTest, AddBlock)
{

  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();
  this->init_hard_fork();

  db_wtxn_guard guard(this->m_db);

  // adding a block with no parent in the blockchain should throw.
  // note: this shouldn't be possible, but is a good (and cheap) failsafe.
  //
  // TODO: need at least one more block to make this reasonable, as the
  // BlockchainDB implementation should not check for parent if
  // no blocks have been added yet (because genesis has no parent).
  //ASSERT_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]), BLOCK_PARENT_DNE);

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]));
  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));

  block b;
  ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0].first)));
  ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0].first)));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  // assert that we can't add the same block twice
  ASSERT_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]), TX_EXISTS);

  for (auto& h : this->m_blocks[0].first.tx_hashes)
  {
    transaction tx;
    ASSERT_TRUE(this->m_db->tx_exists(h));
    ASSERT_NO_THROW(tx = this->m_db->get_tx(h));

    ASSERT_HASH_EQ(h, get_transaction_hash(tx));
  }
}

TYPED_TEST(BlockchainDBTest, RetrieveBlockData)
{
  boost::filesystem::path tempPath = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(dirPath));
  this->get_filenames();
  this->init_hard_fork();

  db_wtxn_guard guard(this->m_db);

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0],  t_diffs[0], t_coins[0], this->m_txs[0]));

  ASSERT_EQ(t_sizes[0], this->m_db->get_block_weight(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_difficulty(0));
  ASSERT_EQ(t_coins[0], this->m_db->get_block_already_generated_coins(0));

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));
  ASSERT_EQ(t_diffs[1] - t_diffs[0], this->m_db->get_block_difficulty(1));

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), this->m_db->get_block_hash_from_height(0));

  std::vector<block> blks;
  ASSERT_NO_THROW(blks = this->m_db->get_blocks_range(0, 1));
  ASSERT_EQ(2, blks.size());
  
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), get_block_hash(blks[0]));
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), get_block_hash(blks[1]));

  std::vector<crypto::hash> hashes;
  ASSERT_NO_THROW(hashes = this->m_db->get_hashes_range(0, 1));
  ASSERT_EQ(2, hashes.size());

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), hashes[0]);
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), hashes[1]);
}

}  // anonymous namespace
