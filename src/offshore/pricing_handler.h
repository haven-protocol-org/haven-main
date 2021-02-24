// Copyright (c) 2019, Haven Protocol
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
#include "pricing_record.h"
#include "cryptonote_basic/cryptonote_basic.h"

namespace offshore {

  class PricingHandler {

  public:

    /**
     * @brief Constructor
     */
    PricingHandler();

    /**
     * @brief Destructor
     */
    ~PricingHandler();

    /**
     * @brief Shutdown the pricing record system (stop the worker thread, etc)
     *
     * @return true on success, false if any shutdown steps fail
     */
    bool deinit();
    
    /**
     * @brief Initialize the pricing record system (start the worker thread, etc)
     *
     * @return true on success, false if any initialization steps fail
     */
    bool init();

    /**
     * @brief Store the current pricing record into the passed-in block
     *
     * @param b the block to update
     *
     * @return true on success, false if any steps fail
     */
    bool store_pricing_record_into_block(cryptonote::block& b);

  private:

    /**
     * @brief Var to hold the latest pricing record, however that may be obtained
     */
    pricing_record m_current_record;
  };
}
