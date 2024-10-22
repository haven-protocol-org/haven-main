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
  { 13, 640650, 0, 1595254800 },  // 20th July 2020 - 15:20 GMT
  { 14, 653565, 0, 1596555180 },  // 7th August 2020 - 15:30 GMT
  { 15, 741957, 0, 1606217525 },  // Fork time is on or around 8th December 2020 at 14:30 GMT. Fork time finalised on 2020-11-24.
  { 16, 831700, 0, 1616597544 },  // Fork time is on or around 12th April 2021 at 12:50 GMT. Fork time finalised on 2021-03-24.
  { 17, 886575, 0, 1624833973 },  // Fork time is on or around 27th June 2021 at 22:26 GMT. Fork time finalised on 2021-07-12. Yes, this is a fork set in the past, because of a chain rollback.
  { 18, 973400, 0, 1636625720 },  // Fork time is on or around 18th November 2021 at 10:30 GMT. Fork time finalised on 2021-11-11.
  { 19, 1033025, 0, 1643968173 }, // Fork time is on or around 9th February 2022 at 11:00 GMT. Fork time finalised on 2022-02-04.
  { 20, 1272875, 0, 1671618321 }, // Fork time is on or around 9th January 2023 at 10:00 GMT. Fork time finalised on 2022-12-21.
  { 21, 1439500, 0, 1690797000 }, // Fork time is on or around 29th August 2023 at 10:00 GMT. Fork time finalised on 2023-07-31.
  { 22, 1439544, 0, 1693999500 }, // Fork time is on or around 29th August 2023 at 12:05 GMT. Fork time finalised on 2023-09-06.
  { 23, 1656000, 0, 1719672007 }, // Fork time is on or around 8th July 2024 at 09:00 GMT. Fork time finalised on 2024-06-29.
  { 24, 1692720, 0, 1724274501 },  // Fork time is on or around 28th August 2024 at 11:00 GMT. Fork time finalised on 2024-09-21.
  { 25, 1732000, 0, 1729588741 },  // Not finalized yet.
  { 26, 1732100, 0, 1729589741 },  // Not finalized yet.
  { 27, 1732200, 0, 1729590741}  // Not finalized yet.
};
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = 1009826;

const hardfork_t testnet_hard_forks[] = {
  // version 1 from the start of the blockchain
  { 1, 1, 0, 1517398420 },
  { 2, 10, 0, 1522713600 },
  { 3, 15, 0, 1528489596 },
  { 4, 20, 0, 1552960800 },
  { 5, 25, 0, 1552980800 },
  { 11, 30, 0, 1593613842 },
  { 13, 35, 0, 1593615042 },
  { 14, 40, 0, 1593616242 },
  { 15, 45, 0, 1593616243 },
  { 16, 50, 0, 1593616244 },
  { 17, 55, 0, 1593619255 },
  { 18, 60, 0, 1593919255 },
  { 19, 65, 0, 1641373507 },
  { 20, 100, 0, 1657094479 },
  { 21, 300, 0, 1680518049 },
  { 22, 400, 0, 1693999500 },
  { 23, 403, 0, 1714641723 },
  { 24, 406, 0, 1724716500 },
  { 25, 410, 0, 1729588741 }
};
const size_t num_testnet_hard_forks = sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = 624633;

const hardfork_t stagenet_hard_forks[] = {
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
  { 16, 230, 0, 1593616244 },
  { 17, 700, 0, 1597456244 },
  { 18, 1000, 0, 1597498244 },
  { 19, 66650, 0, 1643817627 }, // Fork time is on or around 3rd February 2022 at 12:20 GMT. Fork time finalised on 2022-02-02.
  { 20, 256500, 0, 1669894250 } // Fork time is on or around 2st December 2022 at 12:30 GMT. Fork time finalised on 2022-12-01.
};
const size_t num_stagenet_hard_forks = sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
