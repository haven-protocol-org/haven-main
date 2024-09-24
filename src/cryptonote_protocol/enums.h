// Copyright (c) 2019-2022, The Monero Project
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

#pragma once

#include <cstdint>

namespace cryptonote
{
  //! Methods tracking how a tx was received and relayed
  enum class relay_method : std::uint8_t
  {
    none = 0, //!< Received via RPC with `do_not_relay` set
    local,    //!< Received via RPC; trying to send over i2p/tor, etc.
    forward,  //!< Received over i2p/tor; timer delayed before ipv4/6 public broadcast
    stem,     //!< Received/send over network using Dandelion++ stem
    fluff,    //!< Received/sent over network using Dandelion++ fluff
    block     //!< Received in block, takes precedence over others
  };

  enum class transaction_type {
    UNSET = 0,
    TRANSFER,           //!< Transfer of XHV 
    OFFSHORE,           //!< Conversion of XHV to XUSD
    ONSHORE,            //!< Conversion of XUSD to XHV
    OFFSHORE_TRANSFER,  //!< Transfer of XUSD
    XUSD_TO_XASSET,     //!< Conversion of XUSD to non-XHV asset, such as XAU, XAG, XBTC
    XASSET_TO_XUSD,     //!< Conversion assets like XAU, XAG, XBTC (not XHV) to XUSD
    XASSET_TRANSFER     //!< Transfer of asset different from XHV or XUSD, such as XAU, XAG, XBTC 
  };
  //! anonymity pools of the ring signatures.
  //! The supply audit requires that the ring members are split in two distinct anonymity pools, depending on 
  //! whether or not they preceed the block which marks the start of the supply audit.
  //! Transactions should not contain ring members from different anonymity pools. 
  //! Different validation rules will apply, depeneding on the anonymity pool (for example transaction amount might be forced to be revealed for anonnymity pool one)
  enum class anonymity_pool {
    UNSET = 0, //!< anonymity pool not yet initialized
    NOTAPPLICABLE, //!< Transaction is too old, so the pool calculation is not performed
    NONE,      //!< Output is coinbase, so does not belong to any anonymity pool.
    MIXED,     //!< The ring signature contains members from multiple anonymity pools. This is not allowed and such transactions should be rejected.
    POOL_1,    //!< All ring members are from before the supply audit
    POOL_2     //!< All ring members are from after the supply audit
  };
}
