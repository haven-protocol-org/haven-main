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

#include "hardforks.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

const hardfork_t mainnet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1517398427 },
  { 2, 38500, 0, 1522818000 },  // 4th April 2018
  { 3, 89200, 0, 1528942500 },  // 14th June 2018
  { 4, 290587, 0, 1553112000 },  // 20th March 2019 ~20:00 GMT
  { 5, 356338, 0, 1561060800 },  // 20th June 2019 - 20:00 GMT
  { 11, 640640, 0, 1595253600 },  // 20th July 2020 - 15:00 GMT
  { 13, 640650, 0, 1595254800 },   // 20th July 2020 - 15:20 GMT
  { 14, 653565, 0, 1596555180 },   // 7th August 2020 - 15:30 GMT
  { 15, 741957, 0, 1606217525 },   // Fork time is on or around 8th December 2020 at 14:30 GMT. Fork time finalised on 2020-11-24.
  { 16, 831700, 0, 1616597544 }    // Fork time is on or around 12th April 2021 at 12:50 GMT. Fork time finalised on 2021-03-24.
 };
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = 38499;

const hardfork_t testnet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1517398420 },
  { 2, 10, 0, 1522713600 },
  { 3, 20, 0, 1528489596 },
  { 4, 30, 0, 1552960800 },
  { 5, 40, 0, 1552980800 },
  { 11, 50, 0, 1593613842 },
  { 13, 60, 0, 1593615042 },
  { 14, 70, 0, 1593616242 },
  { 15, 150, 0, 1593616243 },
  { 16, 230, 0, 1593616244 }
};
const size_t num_testnet_hard_forks = sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = 24;

const hardfork_t stagenet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1517398420 },
  { 2, 25, 0, 1522713600 },
  { 3, 50, 0, 1528489596 },
  { 4, 75, 0, 1552960800 },
  { 5, 100, 0, 1552980800 },
  { 11, 125, 0, 1593613842 },
  { 13, 135, 0, 1593615042 },
  { 14, 150, 0, 1593616242 },
  { 15, 175, 0, 1593616243 }
};
const size_t num_stagenet_hard_forks = sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
const uint64_t stagenet_hard_fork_version_1_till = 24;
