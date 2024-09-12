// Copyright (c) 2016, Monero Research Labs
// Portions Copyright (c) 2019-2023, Haven Protocol
//
// Author: Shen Noether <shen.noether@gmx.com>
// Authors: neac <neac@havenprotocol.org>, dweab <dweab@havenprotocol.org>, akil <akil@havenprotocol.org>
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

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_protocol/enums.h"
#include "misc_log_ex.h"
#include "misc_language.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "common/util.h"
#include "rctSigs.h"
#include "bulletproofs.h"
#include "bulletproofs_plus.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include <boost/multiprecision/cpp_int.hpp>
#include "offshore/asset_types.h"

#include "bulletproofs.cc"
#include "offshore/pricing_record.cpp"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

using namespace crypto;
using namespace std;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "ringct"

#define CHECK_AND_ASSERT_MES_L1(expr, ret, message) {if(!(expr)) {MCERROR("verify", message); return ret;}}

namespace
{
    rct::Bulletproof make_dummy_bulletproof(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::Bulletproof{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I), I, I, I};
    }

    rct::BulletproofPlus make_dummy_bulletproof_plus(const std::vector<uint64_t> &outamounts, rct::keyV &C, rct::keyV &masks)
    {
        const size_t n_outs = outamounts.size();
        const rct::key I = rct::identity();
        size_t nrl = 0;
        while ((1u << nrl) < n_outs)
          ++nrl;
        nrl += 6;

        C.resize(n_outs);
        masks.resize(n_outs);
        for (size_t i = 0; i < n_outs; ++i)
        {
            masks[i] = I;
            rct::key sv8, sv;
            sv = rct::zero();
            sv.bytes[0] = outamounts[i] & 255;
            sv.bytes[1] = (outamounts[i] >> 8) & 255;
            sv.bytes[2] = (outamounts[i] >> 16) & 255;
            sv.bytes[3] = (outamounts[i] >> 24) & 255;
            sv.bytes[4] = (outamounts[i] >> 32) & 255;
            sv.bytes[5] = (outamounts[i] >> 40) & 255;
            sv.bytes[6] = (outamounts[i] >> 48) & 255;
            sv.bytes[7] = (outamounts[i] >> 56) & 255;
            sc_mul(sv8.bytes, sv.bytes, rct::INV_EIGHT.bytes);
            rct::addKeys2(C[i], rct::INV_EIGHT, sv8, rct::H);
        }

        return rct::BulletproofPlus{rct::keyV(n_outs, I), I, I, I, I, I, I, rct::keyV(nrl, I), rct::keyV(nrl, I)};
    }

    rct::clsag make_dummy_clsag(size_t ring_size)
    {
        const rct::key I = rct::identity();
        const size_t n_scalars = ring_size;
        return rct::clsag{rct::keyV(n_scalars, I), I, I, I};
    }
  /*
  rct::key sm(rct::key y, int n, const rct::key &x)
  {
    while (n--)
      sc_mul(y.bytes, y.bytes, y.bytes);
    sc_mul(y.bytes, y.bytes, x.bytes);
    return y;
  }

  // Compute the inverse of a scalar, the clever way
  rct::key invert(const rct::key &x)
  {
    rct::key _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

    _1 = x;
    sc_mul(_10.bytes, _1.bytes, _1.bytes);
    sc_mul(_100.bytes, _10.bytes, _10.bytes);
    sc_mul(_11.bytes, _10.bytes, _1.bytes);
    sc_mul(_101.bytes, _10.bytes, _11.bytes);
    sc_mul(_111.bytes, _10.bytes, _101.bytes);
    sc_mul(_1001.bytes, _10.bytes, _111.bytes);
    sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
    sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

    rct::key inv;
    sc_mul(inv.bytes, _1111.bytes, _1.bytes);

    inv = sm(inv, 123 + 3, _101);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 4, _1001);
    inv = sm(inv, 2, _11);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 1 + 3, _101);
    inv = sm(inv, 3 + 3, _101);
    inv = sm(inv, 3, _111);
    inv = sm(inv, 1 + 4, _1111);
    inv = sm(inv, 2 + 3, _111);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 2 + 4, _1011);
    inv = sm(inv, 6 + 4, _1001);
    inv = sm(inv, 2 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 3 + 2, _11);
    inv = sm(inv, 1 + 4, _1001);
    inv = sm(inv, 1 + 3, _111);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 1 + 4, _1011);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 2 + 4, _1111);
    inv = sm(inv, 3, _101);
    inv = sm(inv, 1 + 2, _11);

    // Sanity check for successful inversion
    rct::key tmp;
    sc_mul(tmp.bytes, inv.bytes, x.bytes);
    CHECK_AND_ASSERT_THROW_MES(tmp == rct::identity(), "invert failed");
    return inv;
  }
  */  
}

namespace rct {
    Bulletproof proveRangeBulletproof(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        Bulletproof proof = bulletproof_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproof(const Bulletproof &proof)
    {
      try { return bulletproof_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproof(const std::vector<const Bulletproof*> &proofs)
    {
      try { return bulletproof_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    BulletproofPlus proveRangeBulletproofPlus(keyV &C, keyV &masks, const std::vector<uint64_t> &amounts, epee::span<const key> sk, hw::device &hwdev)
    {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == sk.size(), "Invalid amounts/sk sizes");
        masks.resize(amounts.size());
        for (size_t i = 0; i < masks.size(); ++i)
            masks[i] = hwdev.genCommitmentMask(sk[i]);
        BulletproofPlus proof = bulletproof_plus_PROVE(amounts, masks);
        CHECK_AND_ASSERT_THROW_MES(proof.V.size() == amounts.size(), "V does not have the expected size");
        C = proof.V;
        return proof;
    }

    bool verBulletproofPlus(const BulletproofPlus &proof)
    {
      try { return bulletproof_plus_VERIFY(proof); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    bool verBulletproofPlus(const std::vector<const BulletproofPlus*> &proofs)
    {
      try { return bulletproof_plus_VERIFY(proofs); }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    //Borromean (c.f. gmax/andytoshi's paper)
    boroSig genBorromean(const key64 x, const key64 P1, const key64 P2, const bits indices) {
        key64 L[2], alpha;
        auto wiper = epee::misc_utils::create_scope_leave_handler([&](){memwipe(alpha, sizeof(alpha));});
        key c;
        int naught = 0, prime = 0, ii = 0, jj=0;
        boroSig bb;
        for (ii = 0 ; ii < 64 ; ii++) {
            naught = indices[ii]; prime = (indices[ii] + 1) % 2;
            skGen(alpha[ii]);
            scalarmultBase(L[naught][ii], alpha[ii]);
            if (naught == 0) {
                skGen(bb.s1[ii]);
                c = hash_to_scalar(L[naught][ii]);
                addKeys2(L[prime][ii], bb.s1[ii], c, P2[ii]);
            }
        }
        bb.ee = hash_to_scalar(L[1]); //or L[1]..
        key LL, cc;
        for (jj = 0 ; jj < 64 ; jj++) {
            if (!indices[jj]) {
                sc_mulsub(bb.s0[jj].bytes, x[jj].bytes, bb.ee.bytes, alpha[jj].bytes);
            } else {
                skGen(bb.s0[jj]);
                addKeys2(LL, bb.s0[jj], bb.ee, P1[jj]); //different L0
                cc = hash_to_scalar(LL);
                sc_mulsub(bb.s1[jj].bytes, x[jj].bytes, cc.bytes, alpha[jj].bytes);
            }
        }
        return bb;
    }
    
    //see above.
    bool verifyBorromean(const boroSig &bb, const ge_p3 P1[64], const ge_p3 P2[64]) {
        key64 Lv1; key chash, LL;
        int ii = 0;
        ge_p2 p2;
        for (ii = 0 ; ii < 64 ; ii++) {
            // equivalent of: addKeys2(LL, bb.s0[ii], bb.ee, P1[ii]);
            ge_double_scalarmult_base_vartime(&p2, bb.ee.bytes, &P1[ii], bb.s0[ii].bytes);
            ge_tobytes(LL.bytes, &p2);
            chash = hash_to_scalar(LL);
            // equivalent of: addKeys2(Lv1[ii], bb.s1[ii], chash, P2[ii]);
            ge_double_scalarmult_base_vartime(&p2, chash.bytes, &P2[ii], bb.s1[ii].bytes);
            ge_tobytes(Lv1[ii].bytes, &p2);
        }
        key eeComputed = hash_to_scalar(Lv1); //hash function fine
        return equalKeys(eeComputed, bb.ee);
    }

    bool verifyBorromean(const boroSig &bb, const key64 P1, const key64 P2) {
      ge_p3 P1_p3[64], P2_p3[64];
      for (size_t i = 0 ; i < 64 ; ++i) {
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P1_p3[i], P1[i].bytes) == 0, false, "point conv failed");
        CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&P2_p3[i], P2[i].bytes) == 0, false, "point conv failed");
      }
      return verifyBorromean(bb, P1_p3, P2_p3);
    }

    // Generate a CLSAG signature
    // See paper by Goodell et al. (https://eprint.iacr.org/2019/654)
    //
    // The keys are set as follows:
    //   P[l] == p*G
    //   C[l] == z*G
    //   C[i] == C_nonzero[i] - C_offset (for hashing purposes) for all i
    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l, hw::device &hwdev) {
        clsag sig;
        size_t n = P.size(); // ring size
        CHECK_AND_ASSERT_THROW_MES(n == C.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(n == C_nonzero.size(), "Signing and commitment key vector sizes must match!");
        CHECK_AND_ASSERT_THROW_MES(l < n, "Signing index out of range!");

        // Key images
        ge_p3 H_p3;
        hash_to_p3(H_p3,P[l]);
        key H;
        ge_p3_tobytes(H.bytes,&H_p3);

        key D;

        // Initial values
        key a;
        key aG;
        key aH;

        hwdev.clsag_prepare(p,z,sig.I,D,H,a,aG,aH);

        geDsmp I_precomp;
        geDsmp D_precomp;
        precomp(I_precomp.k,sig.I);
        precomp(D_precomp.k,D);

        // Offset key image
        scalarmultKey(sig.D,D,INV_EIGHT);

        // Aggregation hashes
        keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
        sc_0(mu_P_to_hash[0].bytes);
        memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
        sc_0(mu_C_to_hash[0].bytes);
        memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
        for (size_t i = 1; i < n+1; ++i) {
            mu_P_to_hash[i] = P[i-1];
            mu_C_to_hash[i] = P[i-1];
        }
        for (size_t i = n+1; i < 2*n+1; ++i) {
            mu_P_to_hash[i] = C_nonzero[i-n-1];
            mu_C_to_hash[i] = C_nonzero[i-n-1];
        }
        mu_P_to_hash[2*n+1] = sig.I;
        mu_P_to_hash[2*n+2] = sig.D;
        mu_P_to_hash[2*n+3] = C_offset;
        mu_C_to_hash[2*n+1] = sig.I;
        mu_C_to_hash[2*n+2] = sig.D;
        mu_C_to_hash[2*n+3] = C_offset;
        key mu_P, mu_C;
        mu_P = hash_to_scalar(mu_P_to_hash);
        mu_C = hash_to_scalar(mu_C_to_hash);

        // Initial commitment
        keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, aG, aH
        key c;
        sc_0(c_to_hash[0].bytes);
        memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
        for (size_t i = 1; i < n+1; ++i)
        {
            c_to_hash[i] = P[i-1];
            c_to_hash[i+n] = C_nonzero[i-1];
        }
        c_to_hash[2*n+1] = C_offset;
        c_to_hash[2*n+2] = message;

        c_to_hash[2*n+3] = aG;
        c_to_hash[2*n+4] = aH;

        hwdev.clsag_hash(c_to_hash,c);
        
        size_t i;
        i = (l + 1) % n;
        if (i == 0)
            copy(sig.c1, c);

        // Decoy indices
        sig.s = keyV(n);
        key c_new;
        key L;
        key R;
        key c_p; // = c[i]*mu_P
        key c_c; // = c[i]*mu_C
        geDsmp P_precomp;
        geDsmp C_precomp;
        geDsmp H_precomp;
        ge_p3 Hi_p3;

        while (i != l) {
            sig.s[i] = skGen();
            sc_0(c_new.bytes);
            sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
            sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

            // Precompute points
            precomp(P_precomp.k,P[i]);
            precomp(C_precomp.k,C[i]);

            // Compute L
            addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

            // Compute R
            hash_to_p3(Hi_p3,P[i]);
            ge_dsm_precomp(H_precomp.k, &Hi_p3);
            addKeys_aAbBcC(R,sig.s[i],H_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

            c_to_hash[2*n+3] = L;
            c_to_hash[2*n+4] = R;
            hwdev.clsag_hash(c_to_hash,c_new);
            copy(c,c_new);
            
            i = (i + 1) % n;
            if (i == 0)
                copy(sig.c1,c);
        }

        // Compute final scalar
        hwdev.clsag_sign(c,a,p,z,mu_P,mu_C,sig.s[l]);
        memwipe(&a, sizeof(key));

        return sig;
    }

    clsag CLSAG_Gen(const key &message, const keyV & P, const key & p, const keyV & C, const key & z, const keyV & C_nonzero, const key & C_offset, const unsigned int l) {
        return CLSAG_Gen(message, P, p, C, z, C_nonzero, C_offset, l, hw::get_device("default"));
    }

    // MLSAG signatures
    // See paper by Noether (https://eprint.iacr.org/2015/1098)
    // This generalization allows for some dimensions not to require linkability;
    //   this is used in practice for commitment data within signatures
    // Note that using more than one linkable dimension is not recommended.
    mgSig MLSAG_Gen(const key &message, const keyM & pk, const keyV & xx, const unsigned int index, size_t dsRows, hw::device &hwdev) {
        mgSig rv;
        size_t cols = pk.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 2, "Error! What is c if cols = 1!");
        CHECK_AND_ASSERT_THROW_MES(index < cols, "Index out of range");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pk");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_THROW_MES(pk[i].size() == rows, "pk is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "Bad xx size");
        CHECK_AND_ASSERT_THROW_MES(dsRows <= rows, "Bad dsRows size");

        size_t i = 0, j = 0, ii = 0;
        key c, c_old, L, R, Hi;
        ge_p3 Hi_p3;
        sc_0(c_old.bytes);
        vector<geDsmp> Ip(dsRows);
        rv.II = keyV(dsRows);
        keyV alpha(rows);
        auto wiper = epee::misc_utils::create_scope_leave_handler([&](){memwipe(alpha.data(), alpha.size() * sizeof(alpha[0]));});
        keyV aG(rows);
        rv.ss = keyM(cols, aG);
        keyV aHP(dsRows);
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        DP("here1");
        for (i = 0; i < dsRows; i++) {
            toHash[3 * i + 1] = pk[index][i];
            hash_to_p3(Hi_p3, pk[index][i]);
            ge_p3_tobytes(Hi.bytes, &Hi_p3);
            hwdev.mlsag_prepare(Hi, xx[i], alpha[i] , aG[i] , aHP[i] , rv.II[i]);
            toHash[3 * i + 2] = aG[i];
            toHash[3 * i + 3] = aHP[i];
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; //non Double Spendable Rows (see identity chains paper)
        for (i = dsRows, ii = 0 ; i < rows ; i++, ii++) {
            skpkGen(alpha[i], aG[i]); //need to save alphas for later..
            toHash[ndsRows + 2 * ii + 1] = pk[index][i];
            toHash[ndsRows + 2 * ii + 2] = aG[i];
        }

        hwdev.mlsag_hash(toHash, c_old);

        
        i = (index + 1) % cols;
        if (i == 0) {
            copy(rv.cc, c_old);
        }
        while (i != index) {

            rv.ss[i] = skvGen(rows);            
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                hash_to_p3(Hi_p3, pk[i][j]);
                ge_p3_tobytes(Hi.bytes, &Hi_p3);
                addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L; 
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0; j < rows; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            hwdev.mlsag_hash(toHash, c);
            copy(c_old, c);
            i = (i + 1) % cols;
            
            if (i == 0) { 
                copy(rv.cc, c_old);
            }   
        }
        hwdev.mlsag_sign(c, xx, alpha, rows, dsRows, rv.ss[index]);
        return rv;
    }
    
    // MLSAG signatures
    // See paper by Noether (https://eprint.iacr.org/2015/1098)
    // This generalization allows for some dimensions not to require linkability;
    //   this is used in practice for commitment data within signatures
    // Note that using more than one linkable dimension is not recommended.
    bool MLSAG_Ver(const key &message, const keyM & pk, const mgSig & rv, size_t dsRows) {
        size_t cols = pk.size();
        CHECK_AND_ASSERT_MES(cols >= 2, false, "Signature must contain more than one public key");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Bad total row number");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(pk[i].size() == rows, false, "Bad public key matrix dimensions");
        }
        CHECK_AND_ASSERT_MES(rv.II.size() == dsRows, false, "Wrong number of key images present");
        CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad scalar matrix dimensions");
        for (size_t i = 0; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(rv.ss[i].size() == rows, false, "Bad scalar matrix dimensions");
        }
        CHECK_AND_ASSERT_MES(dsRows <= rows, false, "Non-double-spend rows cannot exceed total rows");

        for (size_t i = 0; i < rv.ss.size(); ++i) {
          for (size_t j = 0; j < rv.ss[i].size(); ++j) {
            CHECK_AND_ASSERT_MES(sc_check(rv.ss[i][j].bytes) == 0, false, "Bad signature scalar");
          }
        }
        CHECK_AND_ASSERT_MES(sc_check(rv.cc.bytes) == 0, false, "Bad initial signature hash");

        size_t i = 0, j = 0, ii = 0;
        key c,  L, R;
        key c_old = copy(rv.cc);
        vector<geDsmp> Ip(dsRows);
        for (i = 0 ; i < dsRows ; i++) {
            CHECK_AND_ASSERT_MES(!(rv.II[i] == rct::identity()), false, "Bad key image");
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; // number of dimensions not requiring linkability
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        i = 0;
        while (i < cols) {
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);

                // Compute R directly
                ge_p3 hash8_p3;
                hash_to_p3(hash8_p3, pk[i][j]);
                ge_p2 R_p2;
                ge_double_scalarmult_precomp_vartime(&R_p2, rv.ss[i][j].bytes, &hash8_p3, c_old.bytes, Ip[j].k);
                ge_tobytes(R.bytes, &R_p2);

                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L; 
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0 ; j < rows ; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            c = hash_to_scalar(toHash);
            CHECK_AND_ASSERT_MES(!(c == rct::zero()), false, "Bad signature hash");
            copy(c_old, c);
            i = (i + 1);
        }
        sc_sub(c.bytes, c_old.bytes, rv.cc.bytes);
        return sc_isnonzero(c.bytes) == 0;  
    }
    


    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    rangeSig proveRange(key & C, key & mask, const xmr_amount & amount) {
        sc_0(mask.bytes);
        identity(C);
        bits b;
        d2b(b, amount);
        rangeSig sig;
        key64 ai;
        key64 CiH;
        int i = 0;
        for (i = 0; i < ATOMS; i++) {
            skGen(ai[i]);
            if (b[i] == 0) {
                scalarmultBase(sig.Ci[i], ai[i]);
            }
            if (b[i] == 1) {
                addKeys1(sig.Ci[i], ai[i], H2[i]);
            }
            subKeys(CiH[i], sig.Ci[i], H2[i]);
            sc_add(mask.bytes, mask.bytes, ai[i].bytes);
            addKeys(C, C, sig.Ci[i]);
        }
        sig.asig = genBorromean(ai, sig.Ci, CiH, b);
        return sig;
    }

    //proveRange and verRange
    //proveRange gives C, and mask such that \sumCi = C
    //   c.f. https://eprint.iacr.org/2015/1098 section 5.1
    //   and Ci is a commitment to either 0 or 2^i, i=0,...,63
    //   thus this proves that "amount" is in [0, 2^64]
    //   mask is a such that C = aG + bH, and b = amount
    //verRange verifies that \sum Ci = C and that each Ci is a commitment to 0 or 2^i
    bool verRange(const key & C, const rangeSig & as) {
      try
      {
        PERF_TIMER(verRange);
        ge_p3 CiH[64], asCi[64];
        int i = 0;
        ge_p3 Ctmp_p3 = ge_p3_identity;
        for (i = 0; i < 64; i++) {
            // faster equivalent of:
            // subKeys(CiH[i], as.Ci[i], H2[i]);
            // addKeys(Ctmp, Ctmp, as.Ci[i]);
            ge_cached cached;
            ge_p3 p3;
            ge_p1p1 p1;
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&p3, H2[i].bytes) == 0, false, "point conv failed");
            ge_p3_to_cached(&cached, &p3);
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&asCi[i], as.Ci[i].bytes) == 0, false, "point conv failed");
            ge_sub(&p1, &asCi[i], &cached);
            ge_p3_to_cached(&cached, &asCi[i]);
            ge_p1p1_to_p3(&CiH[i], &p1);
            ge_add(&p1, &Ctmp_p3, &cached);
            ge_p1p1_to_p3(&Ctmp_p3, &p1);
        }
        key Ctmp;
        ge_p3_tobytes(Ctmp.bytes, &Ctmp_p3);
        if (!equalKeys(C, Ctmp))
          return false;
        if (!verifyBorromean(as.asig, asCi, CiH))
          return false;
        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (...) { return false; }
    }

    key get_pre_mlsag_hash(const rctSig &rv, hw::device &hwdev)
    {
      keyV hashes;
      hashes.reserve(3);
      hashes.push_back(rv.message);
      crypto::hash h;

      std::stringstream ss;
      binary_archive<true> ba(ss);
      CHECK_AND_ASSERT_THROW_MES(!rv.mixRing.empty(), "Empty mixRing");
      const size_t inputs = is_rct_simple(rv.type) ? rv.mixRing.size() : rv.mixRing[0].size();
      const size_t outputs = rv.ecdhInfo.size();
      key prehash;
      CHECK_AND_ASSERT_THROW_MES(const_cast<rctSig&>(rv).serialize_rctsig_base(ba, inputs, outputs),
          "Failed to serialize rctSigBase");
      cryptonote::get_blob_hash(ss.str(), h);
      hashes.push_back(hash2rct(h));

      keyV kv;
      if (rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3)
      {
        kv.reserve((6*2+9) * rv.p.bulletproofs.size());
        for (const auto &p: rv.p.bulletproofs)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
          kv.push_back(p.A);
          kv.push_back(p.S);
          kv.push_back(p.T1);
          kv.push_back(p.T2);
          kv.push_back(p.taux);
          kv.push_back(p.mu);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
          kv.push_back(p.a);
          kv.push_back(p.b);
          kv.push_back(p.t);
        }
      }
      else if (rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit)
      {
        kv.reserve((6*2+6) * rv.p.bulletproofs_plus.size());
        for (const auto &p: rv.p.bulletproofs_plus)
        {
          // V are not hashed as they're expanded from outPk.mask
          // (and thus hashed as part of rctSigBase above)
          kv.push_back(p.A);
          kv.push_back(p.A1);
          kv.push_back(p.B);
          kv.push_back(p.r1);
          kv.push_back(p.s1);
          kv.push_back(p.d1);
          for (size_t n = 0; n < p.L.size(); ++n)
            kv.push_back(p.L[n]);
          for (size_t n = 0; n < p.R.size(); ++n)
            kv.push_back(p.R[n]);
        }
      }
      else
      {
        kv.reserve((64*3+1) * rv.p.rangeSigs.size());
        for (const auto &r: rv.p.rangeSigs)
        {
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.asig.s0[n]);
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.asig.s1[n]);
          kv.push_back(r.asig.ee);
          for (size_t n = 0; n < 64; ++n)
            kv.push_back(r.Ci[n]);
        }
      }
      hashes.push_back(cn_fast_hash(kv));
      hwdev.mlsag_prehash(ss.str(), inputs, outputs, hashes, rv.outPk, prehash);
      return  prehash;
    }

    //Ring-ct MG sigs
    //Prove: 
    //   c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10. 
    //   This does the MG sig on the "dest" part of the given key matrix, and 
    //   the last row is the sum of input commitments from that column - sum output commitments
    //   this shows that sum inputs = sum outputs
    //Ver:    
    //   verifies the above sig is created corretly
    mgSig proveRctMG(const key &message, const ctkeyM & pubs, const ctkeyV & inSk, const ctkeyV &outSk, const ctkeyV & outPk, unsigned int index, const key &txnFeeKey, hw::device &hwdev) {
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_THROW_MES(pubs[i].size() == rows, "pubs is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(inSk.size() == rows, "Bad inSk size");
        CHECK_AND_ASSERT_THROW_MES(outSk.size() == outPk.size(), "Bad outSk/outPk size");

        keyV sk(rows + 1);
        keyV tmp(rows + 1);
        size_t i = 0, j = 0;
        for (i = 0; i < rows + 1; i++) {
            sc_0(sk[i].bytes);
            identity(tmp[i]);
        }
        keyM M(cols, tmp);
        //create the matrix to mg sig
        for (i = 0; i < cols; i++) {
            M[i][rows] = identity();
            for (j = 0; j < rows; j++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add input commitments in last row
            }
        }
        sc_0(sk[rows].bytes);
        for (j = 0; j < rows; j++) {
            sk[j] = copy(inSk[j].dest);
            sc_add(sk[rows].bytes, sk[rows].bytes, inSk[j].mask.bytes); //add masks in last row
        }
        for (i = 0; i < cols; i++) {
            for (size_t j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }
        for (size_t j = 0; j < outPk.size(); j++) {
            sc_sub(sk[rows].bytes, sk[rows].bytes, outSk[j].mask.bytes); //subtract output masks in last row..
        }
        mgSig result = MLSAG_Gen(message, M, sk, index, rows, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    //Ring-ct MG sigs Simple
    //   Simple version for when we assume only
    //       post rct inputs
    //       here pubs is a vector of (P, C) length mixin
    //   inSk is x, a_in corresponding to signing index
    //       a_out, Cout is for the output commitment
    //       index is the signing index..
    mgSig proveRctMGSimple(const key &message, const ctkeyV & pubs, const ctkey & inSk, const key &a , const key &Cout, unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        keyV tmp(rows + 1);
        keyV sk(rows + 1);
        size_t i;
        keyM M(cols, tmp);

        sk[0] = copy(inSk.dest);
        sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
        for (i = 0; i < cols; i++) {
            M[i][0] = pubs[i].dest;
            subKeys(M[i][1], pubs[i].mask, Cout);
        }
        mgSig result = MLSAG_Gen(message, M, sk, index, rows, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }

    clsag proveRctCLSAGSimple(const key &message, const ctkeyV &pubs, const ctkey &inSk, const key &a, const key &Cout, unsigned int index, hw::device &hwdev) {
        //setup vars
        size_t rows = 1;
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 1, "Empty pubs");
        keyV tmp(rows + 1);
        keyV sk(rows + 1);
        keyM M(cols, tmp);

        keyV P, C, C_nonzero;
        P.reserve(pubs.size());
        C.reserve(pubs.size());
        C_nonzero.reserve(pubs.size());
        for (const ctkey &k: pubs)
        {
            P.push_back(k.dest);
            C_nonzero.push_back(k.mask);
            rct::key tmp;
            subKeys(tmp, k.mask, Cout);
            C.push_back(tmp);
        }

        sk[0] = copy(inSk.dest);
        sc_sub(sk[1].bytes, inSk.mask.bytes, a.bytes);
        clsag result = CLSAG_Gen(message, P, sk[0], C, sk[1], C_nonzero, Cout, index, hwdev);
        memwipe(sk.data(), sk.size() * sizeof(key));
        return result;
    }


    //Ring-ct MG sigs
    //Prove: 
    //   c.f. https://eprint.iacr.org/2015/1098 section 4. definition 10. 
    //   This does the MG sig on the "dest" part of the given key matrix, and 
    //   the last row is the sum of input commitments from that column - sum output commitments
    //   this shows that sum inputs = sum outputs
    //Ver:    
    //   verifies the above sig is created corretly
    bool verRctMG(const mgSig &mg, const ctkeyM & pubs, const ctkeyV & outPk, const key &txnFeeKey, const key &message) {
        PERF_TIMER(verRctMG);
        //setup vars
        size_t cols = pubs.size();
        CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
        size_t rows = pubs[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Empty pubs");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(pubs[i].size() == rows, false, "pubs is not rectangular");
        }

        keyV tmp(rows + 1);
        size_t i = 0, j = 0;
        for (i = 0; i < rows + 1; i++) {
            identity(tmp[i]);
        }
        keyM M(cols, tmp);

        //create the matrix to mg sig
        for (j = 0; j < rows; j++) {
            for (i = 0; i < cols; i++) {
                M[i][j] = pubs[i][j].dest;
                addKeys(M[i][rows], M[i][rows], pubs[i][j].mask); //add Ci in last row
            }
        }
        for (i = 0; i < cols; i++) {
            for (j = 0; j < outPk.size(); j++) {
                subKeys(M[i][rows], M[i][rows], outPk[j].mask); //subtract output Ci's in last row
            }
            //subtract txn fee output in last row
            subKeys(M[i][rows], M[i][rows], txnFeeKey);
        }
        return MLSAG_Ver(message, M, mg, rows);
    }

    //Ring-ct Simple MG sigs
    //Ver: 
    //This does a simplified version, assuming only post Rct
    //inputs
    bool verRctMGSimple(const key &message, const mgSig &mg, const ctkeyV & pubs, const key & C) {
        try
        {
            PERF_TIMER(verRctMGSimple);
            //setup vars
            size_t rows = 1;
            size_t cols = pubs.size();
            CHECK_AND_ASSERT_MES(cols >= 1, false, "Empty pubs");
            keyV tmp(rows + 1);
            size_t i;
            keyM M(cols, tmp);
            ge_p3 Cp3;
            CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&Cp3, C.bytes) == 0, false, "point conv failed");
            ge_cached Ccached;
            ge_p3_to_cached(&Ccached, &Cp3);
            ge_p1p1 p1;
            //create the matrix to mg sig
            for (i = 0; i < cols; i++) {
                    M[i][0] = pubs[i].dest;
                    ge_p3 p3;
                    CHECK_AND_ASSERT_MES_L1(ge_frombytes_vartime(&p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                    ge_sub(&p1, &p3, &Ccached);
                    ge_p1p1_to_p3(&p3, &p1);
                    ge_p3_tobytes(M[i][1].bytes, &p3);
            }
            //DP(C);
            return MLSAG_Ver(message, M, mg, rows);
        }
        catch (...) { return false; }
    }

    bool verRctCLSAGSimple(const key &message, const clsag &sig, const ctkeyV & pubs, const key & C_offset) {
        try
        {
            PERF_TIMER(verRctCLSAGSimple);
            const size_t n = pubs.size();

            // Check data
            CHECK_AND_ASSERT_MES(n >= 1, false, "Empty pubs");
            CHECK_AND_ASSERT_MES(n == sig.s.size(), false, "Signature scalar vector is the wrong size!");
            for (size_t i = 0; i < n; ++i)
                CHECK_AND_ASSERT_MES(sc_check(sig.s[i].bytes) == 0, false, "Bad signature scalar!");
            CHECK_AND_ASSERT_MES(sc_check(sig.c1.bytes) == 0, false, "Bad signature commitment!");
            CHECK_AND_ASSERT_MES(!(sig.I == rct::identity()), false, "Bad key image!");

            // Cache commitment offset for efficient subtraction later
            ge_p3 C_offset_p3;
            CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&C_offset_p3, C_offset.bytes) == 0, false, "point conv failed");
            ge_cached C_offset_cached;
            ge_p3_to_cached(&C_offset_cached, &C_offset_p3);

            // Prepare key images
            key c = copy(sig.c1);
            key D_8 = scalarmult8(sig.D);
            CHECK_AND_ASSERT_MES(!(D_8 == rct::identity()), false, "Bad auxiliary key image!");
            geDsmp I_precomp;
            geDsmp D_precomp;
            precomp(I_precomp.k,sig.I);
            precomp(D_precomp.k,D_8);

            // Aggregation hashes
            keyV mu_P_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            keyV mu_C_to_hash(2*n+4); // domain, I, D, P, C, C_offset
            sc_0(mu_P_to_hash[0].bytes);
            memcpy(mu_P_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_0,sizeof(config::HASH_KEY_CLSAG_AGG_0)-1);
            sc_0(mu_C_to_hash[0].bytes);
            memcpy(mu_C_to_hash[0].bytes,config::HASH_KEY_CLSAG_AGG_1,sizeof(config::HASH_KEY_CLSAG_AGG_1)-1);
            for (size_t i = 1; i < n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-1].dest;
                mu_C_to_hash[i] = pubs[i-1].dest;
            }
            for (size_t i = n+1; i < 2*n+1; ++i) {
                mu_P_to_hash[i] = pubs[i-n-1].mask;
                mu_C_to_hash[i] = pubs[i-n-1].mask;
            }
            mu_P_to_hash[2*n+1] = sig.I;
            mu_P_to_hash[2*n+2] = sig.D;
            mu_P_to_hash[2*n+3] = C_offset;
            mu_C_to_hash[2*n+1] = sig.I;
            mu_C_to_hash[2*n+2] = sig.D;
            mu_C_to_hash[2*n+3] = C_offset;
            key mu_P, mu_C;
            mu_P = hash_to_scalar(mu_P_to_hash);
            mu_C = hash_to_scalar(mu_C_to_hash);

            // Set up round hash
            keyV c_to_hash(2*n+5); // domain, P, C, C_offset, message, L, R
            sc_0(c_to_hash[0].bytes);
            memcpy(c_to_hash[0].bytes,config::HASH_KEY_CLSAG_ROUND,sizeof(config::HASH_KEY_CLSAG_ROUND)-1);
            for (size_t i = 1; i < n+1; ++i)
            {
                c_to_hash[i] = pubs[i-1].dest;
                c_to_hash[i+n] = pubs[i-1].mask;
            }
            c_to_hash[2*n+1] = C_offset;
            c_to_hash[2*n+2] = message;
            key c_p; // = c[i]*mu_P
            key c_c; // = c[i]*mu_C
            key c_new;
            key L;
            key R;
            geDsmp P_precomp;
            geDsmp C_precomp;
            size_t i = 0;
            ge_p3 hash8_p3;
            geDsmp hash_precomp;
            ge_p3 temp_p3;
            ge_p1p1 temp_p1;

            while (i < n) {
                sc_0(c_new.bytes);
                sc_mul(c_p.bytes,mu_P.bytes,c.bytes);
                sc_mul(c_c.bytes,mu_C.bytes,c.bytes);

                // Precompute points for L/R
                precomp(P_precomp.k,pubs[i].dest);

                CHECK_AND_ASSERT_MES(ge_frombytes_vartime(&temp_p3, pubs[i].mask.bytes) == 0, false, "point conv failed");
                ge_sub(&temp_p1,&temp_p3,&C_offset_cached);
                ge_p1p1_to_p3(&temp_p3,&temp_p1);
                ge_dsm_precomp(C_precomp.k,&temp_p3);

                // Compute L
                addKeys_aGbBcC(L,sig.s[i],c_p,P_precomp.k,c_c,C_precomp.k);

                // Compute R
                hash_to_p3(hash8_p3,pubs[i].dest);
                ge_dsm_precomp(hash_precomp.k, &hash8_p3);
                addKeys_aAbBcC(R,sig.s[i],hash_precomp.k,c_p,I_precomp.k,c_c,D_precomp.k);

                c_to_hash[2*n+3] = L;
                c_to_hash[2*n+4] = R;
                c_new = hash_to_scalar(c_to_hash);
                CHECK_AND_ASSERT_MES(!(c_new == rct::zero()), false, "Bad signature hash");
                copy(c,c_new);

                i = i + 1;
            }
            sc_sub(c_new.bytes,c.bytes,sig.c1.bytes);
            return sc_isnonzero(c_new.bytes) == 0;
        }
        catch (...) { return false; }
    }


    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).    
    void getKeyFromBlockchain(ctkey & a, size_t reference_index) {
        a.mask = pkGen();
        a.dest = pkGen();
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" + 1 columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    tuple<ctkeyM, xmr_amount> populateFromBlockchain(ctkeyV inPk, int mixin) {
        int rows = inPk.size();
        ctkeyM rv(mixin + 1, inPk);
        int index = randXmrAmount(mixin);
        int i = 0, j = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                for (j = 0; j < rows; j++) {
                    getKeyFromBlockchain(rv[i][j], (size_t)randXmrAmount);
                }
            }
        }
        return make_tuple(rv, index);
    }

    //These functions get keys from blockchain
    //replace these when connecting blockchain
    //getKeyFromBlockchain grabs a key from the blockchain at "reference_index" to mix with
    //populateFromBlockchain creates a keymatrix with "mixin" columns and one of the columns is inPk
    //   the return value are the key matrix, and the index where inPk was put (random).     
    xmr_amount populateFromBlockchainSimple(ctkeyV & mixRing, const ctkey & inPk, int mixin) {
        int index = randXmrAmount(mixin);
        int i = 0;
        for (i = 0; i <= mixin; i++) {
            if (i != index) {
                getKeyFromBlockchain(mixRing[i], (size_t)randXmrAmount(1000));
            } else {
                mixRing[i] = inPk;
            }
        }
        return index;
    }

    //RingCT protocol
    //genRct: 
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment 
    //   must know the destination private key to find the correct amount, else will return a random number
    //   Note: For txn fees, the last index in the amounts vector should contain that
    //   Thus the amounts vector will be "one" longer than the destinations vectort
    rctSig genRct(const key &message, const ctkeyV & inSk, const keyV & destinations, const vector<xmr_amount> & amounts, const ctkeyM &mixRing, const keyV &amount_keys, unsigned int index, ctkeyV &outSk, const RCTConfig &rct_config, hw::device &hwdev) {
        CHECK_AND_ASSERT_THROW_MES(amounts.size() == destinations.size() || amounts.size() == destinations.size() + 1, "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(index < mixRing.size(), "Bad index into mixRing");
        for (size_t n = 0; n < mixRing.size(); ++n) {
          CHECK_AND_ASSERT_THROW_MES(mixRing[n].size() == inSk.size(), "Bad mixRing size");
        }
        CHECK_AND_ASSERT_THROW_MES(inSk.size() < 2, "genRct is not suitable for 2+ rings");

        rctSig rv;
        rv.type = RCTTypeFull;
        rv.message = message;
        rv.outPk.resize(destinations.size());
        rv.p.rangeSigs.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        size_t i = 0;
        keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {
            //add destination to sig
            rv.outPk[i].dest = copy(destinations[i]);
            //compute range proof
            rv.p.rangeSigs[i] = proveRange(rv.outPk[i].mask, outSk[i].mask, amounts[i]);
            #ifdef DBG
            CHECK_AND_ASSERT_THROW_MES(verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]), "verRange failed on newly created proof");
            #endif
            //mask amount and mask
            rv.ecdhInfo[i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[i].amount = d2h(amounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit);
        }

        //set txn fee
        if (amounts.size() > destinations.size())
        {
          rv.txnFee = amounts[destinations.size()];
        }
        else
        {
          rv.txnFee = 0;
        }
        key txnFeeKey = scalarmultH(d2h(rv.txnFee));

        rv.mixRing = mixRing;
        rv.p.MGs.push_back(proveRctMG(get_pre_mlsag_hash(rv, hwdev), rv.mixRing, inSk, outSk, rv.outPk, index, txnFeeKey,hwdev));
        return rv;
    }

    rctSig genRct(const key &message, const ctkeyV & inSk, const ctkeyV  & inPk, const keyV & destinations, const vector<xmr_amount> & amounts, const keyV &amount_keys, const int mixin, const RCTConfig &rct_config, hw::device &hwdev) {
        unsigned int index;
        ctkeyM mixRing;
        ctkeyV outSk;
        tie(mixRing, index) = populateFromBlockchain(inPk, mixin);
        return genRct(message, inSk, destinations, amounts, mixRing, amount_keys, index, outSk, rct_config, hwdev);
    }
    
    //RCT simple    
    //for post-rct only
    rctSig genRctSimple(
      const key &message,
      const ctkeyV & inSk,
      const keyV & destinations,
      const cryptonote::transaction_type tx_type,
      const std::string& in_asset_type,
      const vector<xmr_amount> &inamounts,
      const std::vector<size_t>& inamounts_col_indices,
      const vector<xmr_amount> &outamounts,
      const std::map<size_t, std::pair<std::string, std::pair<bool,bool>>>& outamounts_features,
      const xmr_amount txnFee,
      const xmr_amount txnOffshoreFee,
      const xmr_amount onshore_col_amount,
      const ctkeyM & mixRing,
      const keyV &amount_keys,
      const std::vector<unsigned int> & index,
      ctkeyV &outSk,
      uint8_t tx_version,
      const offshore::pricing_record& pr,
      const uint64_t& conversion_rate,
      const uint32_t hf_version,
      const RCTConfig &rct_config,
      hw::device &hwdev
    ){

        const bool bulletproof_or_plus = rct_config.range_proof_type > RangeProofBorromean;
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() > 0, "Empty inamounts");
        CHECK_AND_ASSERT_THROW_MES(inamounts.size() == inSk.size(), "Different number of inamounts/inSk");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == destinations.size(), "Different number of amounts/destinations");
        CHECK_AND_ASSERT_THROW_MES(outamounts.size() == outamounts_features.size(), "Different number of amounts/amount_features");
        CHECK_AND_ASSERT_THROW_MES(amount_keys.size() == destinations.size(), "Different number of amount_keys/destinations");
        CHECK_AND_ASSERT_THROW_MES(index.size() == inSk.size(), "Different number of index/inSk");
        CHECK_AND_ASSERT_THROW_MES(mixRing.size() == inSk.size(), "Different number of mixRing/inSk");
        for (size_t n = 0; n < mixRing.size(); ++n) {
          CHECK_AND_ASSERT_THROW_MES(index[n] < mixRing[n].size(), "Bad index into mixRing");
        }
        //TO-DO##
        rctSig rv;
        if (bulletproof_or_plus)
        {
          switch (rct_config.bp_version)
          {
            case 8:
              rv.type = RCTTypeSupplyAudit;
              break;
            case 0:
            case 7:
              rv.type = RCTTypeBulletproofPlus;
              break;
            case 6:
              rv.type = RCTTypeHaven3;
              break;
            case 5:
              rv.type = RCTTypeHaven2;
              break;
            case 4:
              rv.type = RCTTypeCLSAGN;
              break;
            case 3:
              rv.type = RCTTypeCLSAG;
              break;
            case 2:
              rv.type = RCTTypeBulletproof2;
              break;
            case 1:
              rv.type = RCTTypeBulletproof;
              break;
            default:
              ASSERT_MES_AND_THROW("Unsupported BP version: " << rct_config.bp_version);
          }
        }
        else
          rv.type = RCTTypeSimple;

        using tt = cryptonote::transaction_type;
        bool conversion_tx = tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE || tx_type == tt::XUSD_TO_XASSET || tx_type == tt::XASSET_TO_XUSD;
        bool use_onshore_col = tx_type == tt::ONSHORE && rv.type >= RCTTypeHaven3;
        bool supply_audit_tx = rv.type == RCTTypeSupplyAudit;

        rv.message = message;
        rv.outPk.resize(destinations.size());
        if (!bulletproof_or_plus)
          rv.p.rangeSigs.resize(destinations.size());
        rv.ecdhInfo.resize(destinations.size());

        // initialize the maskSums array
        if (rv.type >= RCTTypeHaven3 && conversion_tx) {
          rv.maskSums.resize(3);
          rv.maskSums[0] = zero();
          rv.maskSums[1] = zero();
          rv.maskSums[2] = zero();
        } else if (rv.type == RCTTypeHaven2) {
          rv.maskSums.resize(2);
          rv.maskSums[0] = zero();
          rv.maskSums[1] = zero();
        }

        size_t i;
        keyV masks(destinations.size()); //sk mask..
        outSk.resize(destinations.size());
        for (i = 0; i < destinations.size(); i++) {

            //add destination to sig
            rv.outPk[i].dest = copy(destinations[i]);
            //compute range proof
            if (!bulletproof_or_plus)
              rv.p.rangeSigs[i] = proveRange(rv.outPk[i].mask, outSk[i].mask, outamounts[i]);
            #ifdef DBG
            if (!bulletproof_or_plus)
                CHECK_AND_ASSERT_THROW_MES(verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]), "verRange failed on newly created proof");
            #endif
        }

        rv.p.bulletproofs.clear();
        rv.p.bulletproofs_plus.clear();
        if (bulletproof_or_plus)
        {
            const bool plus = is_rct_bulletproof_plus(rv.type);
            size_t n_amounts = outamounts.size();
            size_t amounts_proved = 0;
            if (rct_config.range_proof_type == RangeProofPaddedBulletproof)
            {
                rct::keyV C, masks;
                if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
                {
                    // use a fake bulletproof for speed
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(outamounts, C, masks));
                    else
                      rv.p.bulletproofs.push_back(make_dummy_bulletproof(outamounts, C, masks));
                }
                else
                {
                    const epee::span<const key> keys{&amount_keys[0], amount_keys.size()};
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, outamounts, keys, hwdev));
                    else
                      rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, outamounts, keys, hwdev));
                    #ifdef DBG
                    if (plus)
                      CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                    else
                      CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
                    #endif
                }
                for (i = 0; i < outamounts.size(); ++i)
                {
                    rv.outPk[i].mask = rct::scalarmult8(C[i]);
                    outSk[i].mask = masks[i];
                    if (conversion_tx) {
                      // sum the change output masks
                      if (outamounts_features.at(i).first == in_asset_type) {
                        sc_add(rv.maskSums[1].bytes, rv.maskSums[1].bytes, masks[i].bytes);
                      }

                      //RCTTypeAudit should not be used for conversions, only for transfers
                      if (rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus) {
                        // save the collateral output mask for offshore
                        if (tx_type == tt::OFFSHORE && outamounts_features.at(i).second.first) {
                          sc_add(rv.maskSums[2].bytes, rv.maskSums[2].bytes, masks[i].bytes);
                        }

                        // save the actual col output(not change) mask for onshore
                        if (use_onshore_col && outamounts_features.at(i).second.first) {
                          rv.maskSums[2] = masks[i];
                        }
                      }
                    }
                }
            }
            else while (amounts_proved < n_amounts)
            {
                size_t batch_size = 1;
                if (rct_config.range_proof_type == RangeProofMultiOutputBulletproof)
                  while (batch_size * 2 + amounts_proved <= n_amounts && batch_size * 2 <= (plus ? BULLETPROOF_PLUS_MAX_OUTPUTS : BULLETPROOF_MAX_OUTPUTS))
                    batch_size *= 2;
                rct::keyV C, masks;
                std::vector<uint64_t> batch_amounts(batch_size);
                for (i = 0; i < batch_size; ++i)
                  batch_amounts[i] = outamounts[i + amounts_proved];
                if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
                {
                    // use a fake bulletproof for speed
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(make_dummy_bulletproof_plus(batch_amounts, C, masks));
                    else
                      rv.p.bulletproofs.push_back(make_dummy_bulletproof(batch_amounts, C, masks));
                }
                else
                {
                    const epee::span<const key> keys{&amount_keys[amounts_proved], batch_size};
                    if (plus)
                      rv.p.bulletproofs_plus.push_back(proveRangeBulletproofPlus(C, masks, batch_amounts, keys, hwdev));
                    else
                      rv.p.bulletproofs.push_back(proveRangeBulletproof(C, masks, batch_amounts, keys, hwdev));
                #ifdef DBG
                    if (plus)
                      CHECK_AND_ASSERT_THROW_MES(verBulletproofPlus(rv.p.bulletproofs_plus.back()), "verBulletproofPlus failed on newly created proof");
                    else
                      CHECK_AND_ASSERT_THROW_MES(verBulletproof(rv.p.bulletproofs.back()), "verBulletproof failed on newly created proof");
                #endif
                }
                for (i = 0; i < batch_size; ++i)
                {
                  rv.outPk[i + amounts_proved].mask = rct::scalarmult8(C[i]);
                  outSk[i + amounts_proved].mask = masks[i];
                }
                amounts_proved += batch_size;
            }
        }

        key sumout = zero();
        key sumout_onshore_col = zero();
        key atomic = d2h(COIN);
        key inverse_atomic = invert(atomic);
        for (i = 0; i < outSk.size(); ++i)
        {
            key outSk_scaled = zero();
            key tempkey = zero();
            // Convert commitment mask by exchange rate for equalKeys() testing
            if (tx_type == tt::OFFSHORE && outamounts_features.at(i).first == "XUSD") {
              if (hf_version >= HF_VERSION_USE_CONVERSION_RATE) {
                key inverse_rate = invert(d2h(conversion_rate));
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, atomic.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_rate.bytes);
              } else {
                //key inverse_rate = invert(d2h((tx_version >= POU_TRANSACTION_VERSION ? std::min(pr.unused1, pr.xUSD) : pr.unused1)));
                key inverse_rate = invert(d2h((tx_version >= POU_TRANSACTION_VERSION ? pr.min("XHV") : pr.ma("XHV"))));
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, atomic.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_rate.bytes);
              }
            } else if (tx_type == tt::ONSHORE && outamounts_features.at(i).first == "XHV" && !outamounts_features.at(i).second.first && !outamounts_features.at(i).second.second) {
              // HERE BE DRAGONS!!!
              // Unfortunately, because we already had an implementation that used the rate going the wrong way previously,
              // we need to continue supporting that implementation ad-infinitum
              if (hf_version >= HF_VERSION_USE_CONVERSION_RATE) {
                key inverse_rate = invert(d2h(conversion_rate));
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, atomic.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_rate.bytes);
              } else {
                //key rate = d2h(tx_version >= POU_TRANSACTION_VERSION ? std::max(pr.unused1, pr.xUSD) : pr.unused1);
                key rate = d2h(tx_version >= POU_TRANSACTION_VERSION ? pr.max("XHV") : pr.ma("XHV"));
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, rate.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_atomic.bytes);
              }
              // LAND AHOY!!!
            } else if (tx_type == tt::XUSD_TO_XASSET && outamounts_features.at(i).first != "XHV" && outamounts_features.at(i).first != "XUSD") {
              key inverse_rate_xasset = invert(d2h(pr[outamounts_features.at(i).first]));
              sc_mul(tempkey.bytes, outSk[i].mask.bytes, atomic.bytes);
              sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_rate_xasset.bytes);
            } else if (tx_type == tt::XASSET_TO_XUSD && outamounts_features.at(i).first == "XUSD") {
              // HERE BE DRAGONS!!!
              // Unfortunately, because we already had an implementation that used the rate going the wrong way previously,
              // we need to continue supporting that implementation ad-infinitum
              if (hf_version >= HF_VERSION_USE_CONVERSION_RATE) {
                key inverse_rate = invert(d2h(conversion_rate));
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, atomic.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_rate.bytes);
              } else {
                key rate_xasset = d2h(pr[in_asset_type]);
                sc_mul(tempkey.bytes, outSk[i].mask.bytes, rate_xasset.bytes);
                sc_mul(outSk_scaled.bytes, tempkey.bytes, inverse_atomic.bytes);
              }
              // LAND AHOY!!!
            } else {
              outSk_scaled = outSk[i].mask;
            }

            // exclude the onshore collateral outs(actual + change)
            if (use_onshore_col && (outamounts_features.at(i).second.first || outamounts_features.at(i).second.second)) {
              sc_add(sumout_onshore_col.bytes, outSk_scaled.bytes, sumout_onshore_col.bytes);
            } else {
              sc_add(sumout.bytes, outSk_scaled.bytes, sumout.bytes);
            }

            //mask amount and mask
            rv.ecdhInfo[i].mask = copy(outSk[i].mask);
            rv.ecdhInfo[i].amount = d2h(outamounts[i]);
            hwdev.ecdhEncode(rv.ecdhInfo[i], amount_keys[i], rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus);
        }

        //set txn fee
        rv.txnFee = txnFee;
        rv.txnOffshoreFee = txnOffshoreFee;
        rv.mixRing = mixRing;
        keyV &pseudoOuts = bulletproof_or_plus ? rv.p.pseudoOuts : rv.pseudoOuts;
        pseudoOuts.resize(inamounts.size());
        if (is_rct_clsag(rv.type))
            rv.p.CLSAGs.resize(inamounts.size());
        else
            rv.p.MGs.resize(inamounts.size());

        // separete the actual and colleteral inputs
        std::vector<std::pair<size_t, uint64_t>> actual_in_amounts;
        std::vector<std::pair<size_t, uint64_t>> onshore_col_in_amounts;
        for (i = 0; i < inamounts.size(); i++) {
          auto it = std::find(inamounts_col_indices.begin(), inamounts_col_indices.end(), i);
          if (it != inamounts_col_indices.end())
            onshore_col_in_amounts.push_back(std::pair<size_t, uint64_t>(i, inamounts[i]));
          else
            actual_in_amounts.push_back(std::pair<size_t, uint64_t>(i, inamounts[i]));
        }

        // generate commitments per input
        key sumpouts = zero(); //sum pseudoOut masks
        keyV a(inamounts.size());
        for (i = 0 ; i < actual_in_amounts.size() - 1; i++) {
          // Generate a random key
          skGen(a[actual_in_amounts[i].first]);
          // Sum the random keys as we iterate
          sc_add(sumpouts.bytes, a[actual_in_amounts[i].first].bytes, sumpouts.bytes);
          // Generate a commitment to the amount with the random key
          genC(pseudoOuts[actual_in_amounts[i].first], a[actual_in_amounts[i].first], actual_in_amounts[i].second);
        }
        sc_sub(a[actual_in_amounts[i].first].bytes, sumout.bytes, sumpouts.bytes);
        genC(pseudoOuts[actual_in_amounts[i].first], a[actual_in_amounts[i].first], actual_in_amounts[i].second);

        
        //Sum of blinding factors, to be used for the supply audit
        //Defining PseudooutsMaskSums as const, to ensure it is not modified 
        key PseudooutsMaskSumsTemp = zero();
        if (supply_audit_tx) {
          sc_add(PseudooutsMaskSumsTemp.bytes, a[actual_in_amounts[i].first].bytes, sumpouts.bytes);
        }
        const key PseudooutsMaskSums = PseudooutsMaskSumsTemp;

        // set the sum of input blinding factors
        if (conversion_tx) {
          // HERE BE DRAGONS!!!
          // NEAC: Why are we doing math here??? maskSums[0] = sumout
          sc_add(rv.maskSums[0].bytes, a[actual_in_amounts[i].first].bytes, sumpouts.bytes);
          // LAND AHOY!!!
        }

        // generate the commitments for collateral inputs
        if (use_onshore_col) {
          sumpouts = zero();
          for (i = 0; i < onshore_col_in_amounts.size() - 1; i++) {
            // Generate a random key
            skGen(a[onshore_col_in_amounts[i].first]);
            // Sum the random keys as we iterate
            sc_add(sumpouts.bytes, a[onshore_col_in_amounts[i].first].bytes, sumpouts.bytes);
            // Generate a commitment to the amount with the random key
            genC(pseudoOuts[onshore_col_in_amounts[i].first], a[onshore_col_in_amounts[i].first], onshore_col_in_amounts[i].second);
          }
          sc_sub(a[onshore_col_in_amounts[i].first].bytes, sumout_onshore_col.bytes, sumpouts.bytes);
          genC(pseudoOuts[onshore_col_in_amounts[i].first], a[onshore_col_in_amounts[i].first], onshore_col_in_amounts[i].second);
        }
        DP(pseudoOuts[onshore_col_in_amounts[i].first]);
        DP(pseudoOuts[i]);

        key full_message = get_pre_mlsag_hash(rv,hwdev);

        for (i = 0 ; i < inamounts.size(); i++)
        {
            if (is_rct_clsag(rv.type))
            {
                if (hwdev.get_mode() == hw::device::TRANSACTION_CREATE_FAKE)
                    rv.p.CLSAGs[i] = make_dummy_clsag(rv.mixRing[i].size());
                else
                    rv.p.CLSAGs[i] = proveRctCLSAGSimple(full_message, rv.mixRing[i], inSk[i], a[i], pseudoOuts[i], index[i], hwdev);
            }
            else
            {
                rv.p.MGs[i] = proveRctMGSimple(full_message, rv.mixRing[i], inSk[i], a[i], pseudoOuts[i], index[i], hwdev);
            }
        }

        //Add amount proof in case of a supply audit tx
        if (supply_audit_tx){
          //G1=r_r*G
          //K1=r_r*K
          //H1=r_a*H
          //K2=r*K
          //s_r=r_r+r*c
          //s_a=r_a+a*c
          //C=sum of PseudoOuts

          const key zerokey = rct::identity();

          AmountProof amountproof;
          key r_r;
          key r_a;
          key K; //TO-DO## K initialization
          key S; //TO-DO## S initialization
          
          //Calculate sum of pseudoouts
          key sumPseudoOuts=zerokey;
          for (auto po: pseudoOuts){
            addKeys(sumPseudoOuts, sumPseudoOuts, po);
          }

          skGen(r_r); //Generate random r_r
          skGen(r_a); //Generate random r_a
          
          amountproof.G1=scalarmultBase(r_r);
          amountproof.K1=scalarmultKey(K,r_r);
          amountproof.H1=scalarmultH(r_a);
          amountproof.K2=scalarmultKey(K,PseudooutsMaskSums);

          //Challenge c=H(init, G1, K1, H1,K2, C), where C is the sum of pseudoouts
          keyV challenge_to_hash;
          challenge_to_hash.reserve(6);
          key initKey;
          sc_0(initKey.bytes);
          CHECK_AND_ASSERT_THROW_MES(sizeof(initKey.bytes)>=sizeof(config::HASH_KEY_AMOUNTPROOF), "Amount proof hash init string is too long");
          memcpy(initKey.bytes,config::HASH_KEY_AMOUNTPROOF,min(sizeof(config::HASH_KEY_AMOUNTPROOF)-1, sizeof(initKey.bytes)-1));
    
          challenge_to_hash.push_back(initKey);
          challenge_to_hash.push_back(amountproof.G1); 
          challenge_to_hash.push_back(amountproof.K1);
          challenge_to_hash.push_back(amountproof.H1);
          challenge_to_hash.push_back(amountproof.K2);
          challenge_to_hash.push_back(sumPseudoOuts);
          const key c=hash_to_scalar(challenge_to_hash);
          //Calculate s_r
          sc_muladd(amountproof.sr.bytes, r_r.bytes, c.bytes, PseudooutsMaskSums.bytes);
          //Calculate s_a=r_a+c*a
          amountproof.sa=r_a;
          for (auto in_amount: inamounts){ //add (input amounts)*r
            sc_muladd(amountproof.sa.bytes, amountproof.sa.bytes, c.bytes, d2h(in_amount).bytes);
          }

          //Calculate encrypted amount
          rv.amount_encrypted=0;
          for (auto in_amount: inamounts){ //add (input amounts)*r
            rv.amount_encrypted += in_amount;
            CHECK_AND_ASSERT_THROW_MES(rv.amount_encrypted>=in_amount, "Overflow occured, sum of inputs exceeds the maximum xmr amount");
          }
          xmr_amount encryption_key=0;
          const key rS = scalarmultKey(S,PseudooutsMaskSums);
          for (int i = 8; i < 16; i++){ //Use bytes 8 to 16 for the encryption
            encryption_key*=256; //Shift 1 bytes
            encryption_key+=rS.bytes[i];  //Add current byte
          }
          rv.amount_encrypted ^= encryption_key; //XOR using the encryption key
          
          //Post proof
          rv.p.amountproofs.clear();
          rv.p.amountproofs.push_back(amountproof);
        }
        return rv;
    }

    rctSig genRctSimple(
      const key &message,
      const ctkeyV & inSk,
      const ctkeyV & inPk,
      const keyV & destinations,
      const cryptonote::transaction_type tx_type,
      const std::string& in_asset_type,
      const vector<xmr_amount> &inamounts,
      const std::vector<size_t>& inamounts_col_indices,
      const vector<xmr_amount> &outamounts,
      const std::map<size_t, std::pair<std::string, std::pair<bool,bool>>>& outamounts_features,
      const keyV &amount_keys,
      const xmr_amount txnFee,
      const xmr_amount txnOffshoreFee,
      const xmr_amount onshore_col_amount,
      unsigned int mixin,
      uint8_t tx_version,
      const offshore::pricing_record& pr,
      const uint64_t& conversion_rate,
      const uint32_t& hf_version,
      const RCTConfig &rct_config,
      hw::device &hwdev
    ){
        std::vector<unsigned int> index;
        index.resize(inPk.size());
        ctkeyM mixRing;
        ctkeyV outSk;
        mixRing.resize(inPk.size());
        for (size_t i = 0; i < inPk.size(); ++i) {
          mixRing[i].resize(mixin+1);
          index[i] = populateFromBlockchainSimple(mixRing[i], inPk[i], mixin);
        }
        return genRctSimple(message, inSk, destinations, tx_type, in_asset_type, inamounts, inamounts_col_indices, outamounts, outamounts_features, txnFee, txnOffshoreFee, onshore_col_amount, mixRing, amount_keys, index, outSk, tx_version, pr, conversion_rate, hf_version, rct_config, hwdev);
    }

    //RingCT protocol
    //genRct: 
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment 
    //   must know the destination private key to find the correct amount, else will return a random number    
    bool verRct(const rctSig & rv, bool semantics) {
        PERF_TIMER(verRct);
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeFull, false, "verRct called on non-full rctSig");
        if (semantics)
        {
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of outPk and rv.p.rangeSigs");
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
          CHECK_AND_ASSERT_MES(rv.p.MGs.size() == 1, false, "full rctSig has not one MG");
        }
        else
        {
          // semantics check is early, we don't have the MGs resolved yet
        }

        // some rct ops can throw
        try
        {
          if (semantics) {
            tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
            tools::threadpool::waiter waiter(tpool);
            std::deque<bool> results(rv.outPk.size(), false);
            DP("range proofs verified?");
            for (size_t i = 0; i < rv.outPk.size(); i++)
              tpool.submit(&waiter, [&, i] { results[i] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]); });
            if (!waiter.wait())
              return false;

            for (size_t i = 0; i < results.size(); ++i) {
              if (!results[i]) {
                LOG_PRINT_L1("Range proof verified failed for proof " << i);
                return false;
              }
            }
          }

          if (!semantics) {
            //compute txn fee
            key txnFeeKey = scalarmultH(d2h(rv.txnFee));
            bool mgVerd = verRctMG(rv.p.MGs[0], rv.mixRing, rv.outPk, txnFeeKey, get_pre_mlsag_hash(rv, hw::get_device("default")));
            DP("mg sig verified?");
            DP(mgVerd);
            if (!mgVerd) {
              LOG_PRINT_L1("MG signature verification failed");
              return false;
            }
          }

          return true;
        }
        catch (const std::exception &e)
        {
          LOG_PRINT_L1("Error in verRct: " << e.what());
          return false;
        }
        catch (...)
        {
          LOG_PRINT_L1("Error in verRct, but not an actual exception");
          return false;
        }
    }

  // yC = constant for USD/XHV exchange rate
  // Ci = pseudoOuts[i] *** Ci & Di are MUTUALLY EXCLUSIVE
  // fcG' = fee in XHV = 0
  // C'k = outPk[k].mask
  // yD = constant for XHV/USD exchange rate (1/yC)
  // Di = pseudoOuts[i] *** Ci & Di are MUTUALLY EXCLUSIVE
  // fdG' = fee in USD = 0
  // D'k = outPk_usd[k].mask
  //
  //ver RingCT simple
  //assumes only post-rct style inputs (at least for max anonymity)
  bool verRctSemanticsSimple2(
    const rctSig& rv, 
    const offshore::pricing_record& pr,
    const uint64_t& conversion_rate,
    const uint64_t& fee_conversion_rate,
    const uint64_t& tx_fee_conversion_rate,
    const cryptonote::transaction_type& tx_type,
    const std::string& strSource, 
    const std::string& strDest,
    uint64_t amount_burnt,
    const std::vector<cryptonote::tx_out> &vout,
    const std::vector<cryptonote::txin_v> &vin,
    const uint8_t version,
    const uint64_t amount_collateral,
    const uint64_t amount_slippage,
    const cryptonote::anonymity_pool tx_anon_pool
  ){

    try
    {
      PERF_TIMER(verRctSemanticsSimple2);

      tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
      tools::threadpool::waiter waiter(tpool);
      std::deque<bool> results;
      std::vector<const Bulletproof*> proofs;
      std::vector<uint32_t> collateral_indices = {};
      std::vector<uint32_t> collateral_change_indices = {};
      //size_t max_non_bp_proofs = 0, offset = 0;
      using tt = cryptonote::transaction_type;
      using anon = cryptonote::anonymity_pool;
      CHECK_AND_ASSERT_MES(rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit, false, "verRctSemanticsSimple2 called on non-Haven2 rctSig");

      const bool bulletproof = is_rct_bulletproof(rv.type);
      const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
      CHECK_AND_ASSERT_MES(bulletproof || bulletproof_plus, false, "Only bulletproofs supported for Haven2");
      if (bulletproof_plus)
        CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
      else if (bulletproof)
        CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
      CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
      CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
      CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == vin.size(), false, "Mismatched sizes of rv.p.pseudoOuts and vin");
      CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
      CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
      if (rv.type == RCTTypeHaven2) 
        CHECK_AND_ASSERT_MES(rv.maskSums.size() == 2, false, "maskSums size is not 2");
      CHECK_AND_ASSERT_MES(std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strSource) != offshore::ASSET_TYPES.end(), false, "Invalid Source Asset!");
      CHECK_AND_ASSERT_MES(std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strDest) != offshore::ASSET_TYPES.end(), false, "Invalid Dest Asset!");
      CHECK_AND_ASSERT_MES(tx_type != tt::UNSET, false, "Transaction type is not set.");
      //### Anonymity pool sanity checks #####
      CHECK_AND_ASSERT_MES(tx_anon_pool != anon::UNSET, false, "Transaction anonymity pool type is not set.");
      CHECK_AND_ASSERT_MES(tx_anon_pool != anon::MIXED, false, "Transaction has a mixed anonymity pool which is not permited.");
      CHECK_AND_ASSERT_MES(version < HF_VERSION_BURN || tx_anon_pool == anon::POOL_1 || tx_anon_pool == anon::POOL_2, false, "Transaction anonymity pool should be either Pool 1 or Pool 2 during the supply audit");
      //### Supply audit sanity checks #####
      //This check ensures old funds can't be spent after the audit is over.
      const bool before_supply_audit = (version < HF_VERSION_SUPPLY_AUDIT);
      const bool during_supply_audit = (version >=HF_VERSION_SUPPLY_AUDIT && version < HF_VERSION_SUPPLY_AUDIT_END);
      const bool after_supply_audit = (version >= HF_VERSION_SUPPLY_AUDIT_END);
      int num_epochs=(before_supply_audit ? 1 : 0)+(during_supply_audit ? 1 : 0)+(after_supply_audit ? 1 : 0);
      CHECK_AND_ASSERT_MES(num_epochs==1, false, "Failed to determine if the current block is before, during, or after the supply audit");
      if (before_supply_audit){ // Audit transactions not permited
        CHECK_AND_ASSERT_MES(rv.type != RCTTypeSupplyAudit, false, "Audit transactions permited only during the audit period");  
      }
      if (during_supply_audit){ //Conversions disabled, Audit tx spends from Pool 1, non-Audit spends from Pool 2, burn not permited 
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit, false, "Only RCTTypeBulletproofPlus and Audit transactions permited after the supply Audit");
        if (rv.type == RCTTypeSupplyAudit)
          CHECK_AND_ASSERT_MES(tx_anon_pool != anon::POOL_1, false, "Supply audit transactions should have anonymity pool 1");
        if (rv.type == RCTTypeBulletproofPlus)
          CHECK_AND_ASSERT_MES(tx_anon_pool != anon::POOL_2, false, "Regular transactions after the audit start should have anonymity pool 2");
        CHECK_AND_ASSERT_MES(tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER, false, "Only transfers allowed during the supply audit period");
        CHECK_AND_ASSERT_MES(amount_burnt==0, false, "Burn transaction not allowed during the supply audit period");
      }
      if (after_supply_audit){ // All transactions spent from Pool 2, audit tx not permited 
        CHECK_AND_ASSERT_MES(tx_anon_pool != anon::POOL_2, false, "Transactions after the audit end should have anonymity pool 2");
        CHECK_AND_ASSERT_MES(rv.type != RCTTypeSupplyAudit, false, "Audit transactions permited only during the audit period");  
      }
      //Supply audit transaction should have one amount proof, and only audit transactions should have an amount proof
      if (rv.type == RCTTypeSupplyAudit)
        CHECK_AND_ASSERT_MES(rv.p.amountproofs.size()==1, false, "Supply audit transaction found without amount proofs");
      if (!rv.p.amountproofs.empty())
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSupplyAudit, false, "Amount proof for non-audit transaction found");
      
       
      CHECK_AND_ASSERT_MES((strSource != strDest) == (tx_type == tt::ONSHORE || tx_type==tt::OFFSHORE || tx_type==tt::XASSET_TO_XUSD || tx_type == tt::XUSD_TO_XASSET), false, "Mismatch between source/dest assets and transaction type");
      if (strSource != strDest) {
        CHECK_AND_ASSERT_MES(!pr.empty(), false, "Empty pricing record found for a conversion tx");
        CHECK_AND_ASSERT_MES(amount_burnt, false, "0 amount_burnt found for a conversion tx");
        CHECK_AND_ASSERT_MES(rv.type != RCTTypeSupplyAudit, false, "Supply audit tx cannot be a conversion tx"); //redundant, paranoid check
        if (rv.type >= RCTTypeHaven3) {
          CHECK_AND_ASSERT_MES(rv.maskSums.size() == 3, false, "maskSums size is not correct");
          if (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE)
            CHECK_AND_ASSERT_MES(amount_collateral, false, "0 collateral requirement something went wrong! rejecting tx..");
        }
        CHECK_AND_ASSERT_MES(version < HF_VERSION_MAX_CONV_TRANSACTION_FEE || rv.txnFee < MAX_CONV_TRANSACTION_FEE, false, "Transaction fee too high! rejecting tx..");
      }

      if (strSource == strDest) {
        CHECK_AND_ASSERT_MES(pr.empty(), false, "Pricing record found for a transfer! rejecting tx..");
        CHECK_AND_ASSERT_MES(amount_collateral==0, false, "Collateral found for a transfer! rejecting tx..");
        CHECK_AND_ASSERT_MES(amount_slippage==0, false, "Slippage found for a transfer! rejecting tx..");
        if (version < HF_VERSION_BURN) {
          CHECK_AND_ASSERT_MES(amount_burnt==0, false, "amount_burnt found for a transfer tx! rejecting tx.. ");
          }
      }
      
      if (version >= HF_VERSION_SUPPLY_AUDIT && rv.type != RCTTypeSupplyAudit){ //Another redundant paranoid check related to the pool split, but we really do not want old funds to be spendable
        for (auto inp: vin) {
          cryptonote::txin_haven_key inp_haven_key=boost::get<cryptonote::txin_haven_key>(inp);
          CHECK_AND_NO_ASSERT_MES(inp_haven_key.key_offsets.size()>0, false, "Input without decoys found");
          //TO-DO## Somehow get the first "new" output instead of 100
          CHECK_AND_NO_ASSERT_MES(inp_haven_key.key_offsets[0]>100, false, "Input seems too old");
        }
      }

      uint64_t amount_supply_burnt = 0;

      if ((tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER) && version >= HF_VERSION_BURN && amount_burnt>0){
        amount_supply_burnt = amount_burnt;
      }
      

      // OUTPUTS SUMMED FOR EACH COLOUR
      key zerokey = rct::identity();
      // Zi is intentionally set to a different value to zerokey, so that if a bug is introduced in the later logic, any comparison with zerokey will fail
      key Zi = scalarmultH(d2h(1));

      // Calculate sum of all C' and D'
      rct::keyV masks_C;
      rct::keyV masks_D;
      for (size_t i=0; i<vout.size(); i++) {

        bool is_collateral = false;
        bool is_collateral_change = false;
        bool ok = cryptonote::is_output_collateral(vout[i], is_collateral, is_collateral_change);
        if (!ok) {
          LOG_ERROR("Failed to get output collateral status");
          return false;
        }
        if (is_collateral) {
          collateral_indices.push_back(i);
        }
        if (is_collateral_change) {
          collateral_change_indices.push_back(i);
        }
        
        std::string output_asset_type;
        ok = cryptonote::get_output_asset_type(vout[i], output_asset_type);
        if (!ok) {
          LOG_ERROR("Failed to get output type");
          return false;
        }
        
        if (version >= HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS && (is_collateral || is_collateral_change) && output_asset_type != "XHV"){
          LOG_ERROR("Collateral which is not XHV found");
          return false;  
        }

        // Don't exclude the onshore collateral ouputs from proof-of-value calculation
        if (output_asset_type == strSource) {
          masks_C.push_back(rv.outPk[i].mask);
        } else if (output_asset_type == strDest) {
          masks_D.push_back(rv.outPk[i].mask);
        } else {
          LOG_ERROR("Invalid output detected (wrong asset type)");
          return false;
        }
      }

      // Sanity check the collateral
      bool collateral_exploit = false;
      if ((version >= HF_VERSION_USE_COLLATERAL) &&
          (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE)) {
        if (collateral_indices.size() != 1) {
          LOG_ERROR("Incorrect number of collateral outputs provided");
          if (version >= HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS)
            return false;
          else
            collateral_exploit = true;
        } else if ((tx_type == tt::OFFSHORE && collateral_change_indices.size() != 0)  ||
                   (tx_type == tt::ONSHORE && collateral_change_indices.size() != 1)) {
          LOG_ERROR("Incorrect number of collateral change outputs provided");
          if (version >= HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS)
            return false;
          else
            collateral_exploit = true;
        } else if (tx_type == tt::ONSHORE && collateral_indices[0] == collateral_change_indices[0]) {
          LOG_ERROR("Collateral output cannot also be collateral_change output");
          return false;
        }
      }
      
      key sumOutpks_C = addKeys(masks_C);
      key sumOutpks_D = addKeys(masks_D);
      DP(sumOutpks_C);
      DP(sumOutpks_D);

      // FEES FOR EACH COLOUR
      // Calculate tx fee for C colour
      key txnFeeKey = scalarmultH(d2h(rv.txnFee));
      // Calculate offshore conversion fee (also always in C colour)
      key txnOffshoreFeeKey = scalarmultH(d2h(rv.txnOffshoreFee));
      // Calculate the supply burn (also always in C colour)
      key amount_supply_burntKey = scalarmultH(d2h(amount_supply_burnt));

      // Sum the consumed outputs in their respective asset types (sumColIns = inputs in D)
      key sumPseudoOuts = zerokey;
      key sumColIns = zerokey;
      if (tx_type == tt::ONSHORE && version >= HF_VERSION_USE_COLLATERAL) {
        for (size_t i = 0; i < rv.p.pseudoOuts.size(); ++i) {
          if (boost::get<cryptonote::txin_haven_key>(vin[i]).asset_type == "XHV") {
            sumColIns = addKeys(sumColIns, rv.p.pseudoOuts[i]);
          } else {
            sumPseudoOuts = addKeys(sumPseudoOuts, rv.p.pseudoOuts[i]);
          }
        }
      } else {
        sumPseudoOuts = addKeys(rv.p.pseudoOuts);
      }
      DP(sumPseudoOuts);

      // C COLOUR
      key sumC;
      // Remove the outputs from the inputs
      subKeys(sumC, sumPseudoOuts, sumOutpks_C);

      // D COLOUR
      key sumD;
      // Subtract the sum of converted output commitments from the sum of consumed output commitments in D colour (if any are present)
      // (Note: there are only consumed output commitments in D colour if the transaction is an onshore and requires collateral)
      subKeys(sumD, sumColIns, sumOutpks_D);

      //Remove burnt supply
      subKeys(sumC, sumC, amount_supply_burntKey);

      if (version >= HF_VERSION_CONVERSION_FEES_IN_XHV) {
        // NEAC: Convert the fees for conversions to XHV
        if (tx_type == tt::TRANSFER || tx_type == tt::OFFSHORE || tx_type == tt::OFFSHORE_TRANSFER || tx_type == tt::XASSET_TRANSFER) {
          // All transfer types and offshores have fees in source asset type = C colour
          subKeys(sumC, sumC, txnFeeKey);
          subKeys(sumC, sumC, txnOffshoreFeeKey);
        } else {//if (tx_type == tt::ONSHORE) {

          // Calculate what the transaction fee is in C terms
          boost::multiprecision::uint128_t tx_fee_128 = rv.txnFee; // Fee stored in XHV
          tx_fee_128 *= tx_fee_conversion_rate;
          tx_fee_128 /= COIN;
          key txnFeeKeyInC = scalarmultH(d2h(tx_fee_128.convert_to<uint64_t>()));

          // Deduct the transaction fee from our sum of C terms
          subKeys(sumC, sumC, txnFeeKeyInC);

          // Verify the amount of the conversion fee, starting with amount_burnt
          boost::multiprecision::uint128_t fee_128 = amount_burnt;
          fee_128 *= 3;
          fee_128 /= 200; // This is the correct fee in xUSD
          boost::multiprecision::uint128_t conversion_fee_128 = fee_128;
          conversion_fee_128 *= fee_conversion_rate;
          conversion_fee_128 /= COIN;
          if (conversion_fee_128 != rv.txnOffshoreFee) {
            LOG_ERROR("Incorrect conversion fee: expected " << conversion_fee_128.convert_to<uint64_t>() << " but received " << rv.txnOffshoreFee << " - aborting");
            return false;
          }

          // Deduct the conversion fee from our C terms
          key txnOffshoreFeeKeyInC = scalarmultH(d2h(fee_128.convert_to<uint64_t>()));
          subKeys(sumC, sumC, txnOffshoreFeeKeyInC);
        }
      } else {
        // Prior to BP+, all fees were in C colour
        subKeys(sumC, sumC, txnFeeKey);
        subKeys(sumC, sumC, txnOffshoreFeeKey);
      }

      if (version >= HF_VERSION_USE_CONVERSION_RATE) {

        if (strSource != strDest) {

          if (version >= HF_VERSION_SLIPPAGE) {
            // Handle any slippage (NEAC: should always be zero for non-conversions!)
            key slippageKey = scalarmultH(d2h(amount_slippage));
            subKeys(sumC, sumC, slippageKey);
          }
          
          // Scale D terms by the conversion rate (NEAC: should always be COIN for non-conversions!)
          key D_scaled = scalarmultKey(sumD, d2h(COIN));
          key yC_invert = invert(d2h(conversion_rate));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumC, D_final);
        } else {
          Zi = addKeys(sumC, sumD);          
        }
        
      } else {
      
        // NEAC: attempt to only calculate forward
        // CALCULATE Zi
        if (tx_type == tt::OFFSHORE) {
          key D_scaled = scalarmultKey(sumD, d2h(COIN));
          key yC_invert = invert(d2h((version >= HF_PER_OUTPUT_UNLOCK_VERSION) ? pr.min("XHV") : pr.ma("XHV")));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumC, D_final);
        } else if (tx_type == tt::ONSHORE) {
          key D_scaled = scalarmultKey(sumD, d2h((version >= HF_PER_OUTPUT_UNLOCK_VERSION) ? pr.max("XHV") : pr.ma("XHV")));
          key yC_invert = invert(d2h(COIN));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumC, D_final);
        } else if (tx_type == tt::OFFSHORE_TRANSFER) {
          Zi = addKeys(sumC, sumD);
        } else if (tx_type == tt::XUSD_TO_XASSET) {
          key D_scaled = scalarmultKey(sumD, d2h(COIN));
          key yC_invert = invert(d2h(pr[strDest]));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumC, D_final);
        } else if (tx_type == tt::XASSET_TO_XUSD) {
          key D_scaled = scalarmultKey(sumD, d2h(pr[strSource]));
          key yC_invert = invert(d2h(COIN));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumC, D_final);
        } else if (tx_type == tt::XASSET_TRANSFER) {
          Zi = addKeys(sumC, sumD);
        } else if (tx_type == tt::TRANSFER) {
          Zi = addKeys(sumC, sumD);
        } else {
          LOG_PRINT_L1("Invalid transaction type specified");
          return false;
        }
      }
      
      //check Zi == 0
      if (!equalKeys(Zi, zerokey)) {
        LOG_ERROR("Sum check failed (Zi)");
        if (collateral_exploit && version < HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS) {
          // Allow the single known exploit TX 8edb1b619518fe8c1429697b702fd8d350139124333dc5d1fee79f6d28c440cc through, so we can lock it
        } else {
          return false;
        }
      }

      // Validate TX amount burnt/mint for conversions
      if (strSource != strDest) {

        if (version >= HF_VERSION_SLIPPAGE) {
          // Subtract the slippage from the amount_burnt
          // Check for potential underflow and fail
          if (amount_burnt<amount_slippage) {
            LOG_ERROR("Slippage exceeds burnt amount");
            return false; 
          }
          amount_burnt -= amount_slippage;
        }

        if ((version < HF_VERSION_USE_COLLATERAL) && (tx_type == tt::XASSET_TO_XUSD || tx_type == tt::XUSD_TO_XASSET)) {
          // Wallets must append the burnt fee for xAsset conversions to the amount_burnt.
          // So we subtract that from amount_burnt and validate only the actual coversion amount because
          // fees are not converted. They are just burned.

          // calculate the burnt fee. Should be the 80% of the offshoreFee
          boost::multiprecision::uint128_t fee_128 = rv.txnOffshoreFee;
          boost::multiprecision::uint128_t burnt_fee = (fee_128 * 4) / 5;

          // subtract it from amount burnt
          amount_burnt -= (uint64_t)burnt_fee;
        }

        // m = sum of all masks of inputs
        // n = sum of masks of change + collateral outputs
        // rv.maskSums[0] = m
        // rv.maskSums[1] = n
        // The value the current sumC is C = xG + aH where 
        // x = m - n, a = actual converted amount(burnt), and G, H are constants

        // add the n back to x, so x = m in calculation C = xG + aH
        // but we can't add it directly. So first calculate the C for n(mask) and 0(amount)
        key C_n;
        genC(C_n, rv.maskSums[1], 0);
        key C_burnt = addKeys(sumC, C_n);

        // Now, x actually should be rv.maskSums[0]
        // so if we calculate a C with rv.maskSums[0] and amount_burnt, C should be same as C_burnt
        key pseudoC_burnt;
        genC(pseudoC_burnt, rv.maskSums[0], amount_burnt);

        // check whether they are equal
        if (!equalKeys(C_burnt, pseudoC_burnt)) {
          LOG_PRINT_L1("Tx amount burnt/minted validation failed.");
          return false;
        }
      }

      // validate the collateral
      if ((version >= HF_VERSION_USE_COLLATERAL)) {

        if (tx_type == tt::OFFSHORE || tx_type == tt::ONSHORE) {

          // get collateral commitment
          key C_col = rv.outPk[collateral_indices[0]].mask;

          // calculate needed commitment
          key pseudoC_col;
          genC(pseudoC_col, rv.maskSums[2], amount_collateral);

          if (!equalKeys(pseudoC_col, C_col)) {
            LOG_ERROR("Collateral commitment verification failed.");
            if (collateral_exploit && version < HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS) {
              // Allow the single known exploit TX 8edb1b619518fe8c1429697b702fd8d350139124333dc5d1fee79f6d28c440cc through, so we can lock it
            } else {
              return false;
            }
          }

          if (tx_type == tt::ONSHORE) {

            // check collateral inputs == outputs
            key sumColOut = addKeys(rv.outPk[collateral_indices[0]].mask, rv.outPk[collateral_change_indices[0]].mask);
            if (!equalKeys(sumColOut, sumColIns)) {
              LOG_ERROR("Onshore collateral inputs != outputs");
              if (collateral_exploit && version < HF_VERSION_ADDITIONAL_COLLATERAL_CHECKS) {
                // Allow the single known exploit TX 8edb1b619518fe8c1429697b702fd8d350139124333dc5d1fee79f6d28c440cc through, so we can lock it
              } else {
                return false;
              }
            }
          }
        }
      }

      for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
        proofs.push_back(&rv.p.bulletproofs[i]);
    
      if (!proofs.empty() && !verBulletproof(proofs))
      {
        LOG_PRINT_L1("Aggregate range proof verified failed");
        return false;
      }
      
      //Supply proof check

      if(rv.type==RCTTypeSupplyAudit){
        if(rv.p.amountproofs.empty() || ! verAmountproof(rv.p.amountproofs[0], rv.p.pseudoOuts)) {
          LOG_PRINT_L1("Amount proof verified failed for an audit transaction");
          return false;
        }
      }

      return true;
    }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (const std::exception &e)
    {
      LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
      return false;
    }
    catch (...)
    {
      LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
      return false;
    }
  }
  
  // yC = constant for USD/XHV exchange rate
  // Ci = pseudoOuts[i] *** Ci & Di are MUTUALLY EXCLUSIVE
  // fcG' = fee in XHV = 0
  // C'k = outPk[k].mask
  // yD = constant for XHV/USD exchange rate (1/yC)
  // Di = pseudoOuts[i] *** Ci & Di are MUTUALLY EXCLUSIVE
  // fdG' = fee in USD = 0
  // D'k = outPk_usd[k].mask
  //
    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
  bool verRctSemanticsSimple(
    const rctSig& rv, 
    const offshore::pricing_record& pr, 
    const cryptonote::transaction_type& type,
    const std::string& strSource, 
    const std::string& strDest
  ){
    try
      {
        PERF_TIMER(verRctSemanticsSimple);

        tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
        tools::threadpool::waiter waiter(tpool);
        std::deque<bool> results;

        std::vector<const Bulletproof*> proofs;
        size_t max_non_bp_proofs = 0, offset = 0;

        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN,
                             false, "verRctSemanticsSimple called on non simple rctSig");
        
        const bool bulletproof = is_rct_bulletproof(rv.type);
        if (bulletproof)
          {
            CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
            if ((rv.type == RCTTypeCLSAG) || (rv.type == RCTTypeCLSAGN))
              {
                CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
                CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
              }
            else
              {
                CHECK_AND_ASSERT_MES(rv.p.CLSAGs.empty(), false, "CLSAGs are not empty for MLSAG");
                CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.MGs");
              }
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
          }
        else
          {
            CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of outPk and rv.p.rangeSigs");
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.pseudoOuts and rv.p.MGs");
            CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.empty(), false, "rv.p.pseudoOuts is not empty");
          }
        CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");
        CHECK_AND_ASSERT_MES(std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strSource) != offshore::ASSET_TYPES.end(), false, "Invalid Source Asset!");
        CHECK_AND_ASSERT_MES(std::find(offshore::ASSET_TYPES.begin(), offshore::ASSET_TYPES.end(), strDest) != offshore::ASSET_TYPES.end(), false, "Invalid Dest Asset!");
        CHECK_AND_ASSERT_MES(type != cryptonote::transaction_type::UNSET, false, "Invalid transaction type.");
        if (strSource != strDest) {
          CHECK_AND_ASSERT_MES(!pr.empty(), false, "Empty pr found for a conversion tx");
        }
      
        if (!bulletproof)
          max_non_bp_proofs += rv.p.rangeSigs.size();

        results.resize(max_non_bp_proofs);

        const keyV &pseudoOuts = bulletproof ? rv.p.pseudoOuts : rv.pseudoOuts;

        // OUTPUTS SUMMED FOR EACH COLOUR
        key zerokey = rct::identity();
        // Zi is intentionally set to a different value to zerokey, so that if a bug is introduced in the later logic, any comparison with zerokey will fail
        key Zi = scalarmultH(d2h(1));

        // Calculate sum of all C'
        rct::keyV masks(rv.outPk.size());
        for (size_t i = 0; i < rv.outPk.size(); i++) {
          masks[i] = rv.outPk[i].mask;
        }
        key sumOutpks = addKeys(masks);
        DP(sumOutpks);

        // Calculate sum of all D'
        rct::keyV masks_usd(rv.outPk_usd.size());
        for (size_t i = 0; i < rv.outPk_usd.size(); i++) {
          masks_usd[i] = rv.outPk_usd[i].mask;
        }
        key sumOutpks_usd = addKeys(masks_usd);
        DP(sumOutpks_usd);

        // Calculate sum of all E' (xAssets)
        rct::keyV masks_xasset(rv.outPk_xasset.size());
        for (size_t i = 0; i < rv.outPk_xasset.size(); i++) {
          masks_xasset[i] = rv.outPk_xasset[i].mask;
        }
        key sumOutpks_xasset = addKeys(masks_xasset);
        DP(sumOutpks_xasset);

        // FEES FOR EACH COLOUR
        const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
        const key txnOffshoreFeeKey = scalarmultH(d2h(rv.txnOffshoreFee));
        const key txnFeeKey_usd = scalarmultH(d2h(rv.txnFee_usd));
        const key txnOffshoreFeeKey_usd = scalarmultH(d2h(rv.txnOffshoreFee_usd));
        const key txnFeeKey_xasset = scalarmultH(d2h(rv.txnFee_xasset));
        const key txnOffshoreFeeKey_xasset = scalarmultH(d2h(rv.txnOffshoreFee_xasset));

        /*
          offshore TX:
          sumPseudoOuts = addKeys(pseudoOuts); (total of inputs)
          sumPseudoOuts_usd = zerokey; (no input usd amount)

          sumXHV = total_output_value_in_XHV (after subtracting fees)
          sumUSD = -total_output_value_in_USD

          D_scaled = sumUSD 
          yC_invert = 1 / exchange_rate_in_usd
          D_final = -total_output_value_in_XHV
          Zi = total_output_value_in_XHV - total_output_value_in_XHV = 0; 


          XUSD -> XASSET TX:
          sumPseudoOuts_usd = total_input_in_usd
          sumPseudoOuts_xasset = zerokey; (no input xasset amount)


          sumUSD = total_output_value_in_USD (after subtracting fees)
          sumXASSET = -total_output_value_in_XASSET (without fees)

          D_scaled = sumXASSET
          y = exchange_rate_in_usd
          D_final = sumXASSET * 1/ exchange_rate_in_usd = -total_output_value_in_USD
          Zi = sumUSD + D_final = 0
        */
        using tx_type = cryptonote::transaction_type;
        key sumPseudoOuts = (strSource == "XHV") ? addKeys(pseudoOuts) : zerokey;
        key sumPseudoOuts_usd = (strSource == "XUSD") ? addKeys(pseudoOuts) : zerokey;
        key sumPseudoOuts_xasset = (strSource != "XHV" && strSource != "XUSD") ? addKeys(pseudoOuts) : zerokey;
        
        DP(sumPseudoOuts);
        DP(sumPseudoOuts_usd);
        DP(sumPseudoOuts_xasset);

        // C COLOUR
        key sumXHV;
        // Remove the fees
        subKeys(sumXHV, sumPseudoOuts, txnFeeKey);
        subKeys(sumXHV, sumXHV, txnOffshoreFeeKey);
        subKeys(sumXHV, sumXHV, sumOutpks);

        // Variant COLOUR (C or D depending on the direction of the transaction)
        key sumUSD;
        // Remove the fees
        subKeys(sumUSD, sumPseudoOuts_usd, txnFeeKey_usd);
        subKeys(sumUSD, sumUSD, txnOffshoreFeeKey_usd);
        subKeys(sumUSD, sumUSD, sumOutpks_usd);

        // D COLOUR
        key sumXASSET;
        // Remove the fees
        subKeys(sumXASSET, sumPseudoOuts_xasset, txnFeeKey_xasset);
        subKeys(sumXASSET, sumXASSET, txnOffshoreFeeKey_xasset);
        subKeys(sumXASSET, sumXASSET, sumOutpks_xasset);

        // NEAC: attempt to only calculate forward
        // CALCULATE Zi
        if (type == tx_type::OFFSHORE) {
          key D_scaled = scalarmultKey(sumUSD, d2h(COIN));
          key yC_invert = invert(d2h(pr.ma("XHV")));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumXHV, D_final);
        } else if (type == tx_type::ONSHORE) {
          key C_scaled = scalarmultKey(sumXHV, d2h(pr.ma("XHV")));
          key yD_invert = invert(d2h(COIN));
          key C_final = scalarmultKey(C_scaled, yD_invert);
          Zi = addKeys(C_final, sumUSD);
        } else if (type == tx_type::OFFSHORE_TRANSFER) {
          Zi = addKeys(sumXHV, sumUSD);
        } else if (type == tx_type::XUSD_TO_XASSET) {
          key D_scaled = scalarmultKey(sumXASSET, d2h(COIN));
          key yC_invert = invert(d2h(pr[strDest]));
          key D_final = scalarmultKey(D_scaled, yC_invert);
          Zi = addKeys(sumUSD, D_final);
        } else if (type == tx_type::XASSET_TO_XUSD) {
          key C_scaled = scalarmultKey(sumUSD, d2h(pr[strSource]));
          key yD_invert = invert(d2h(COIN));
          key C_final = scalarmultKey(C_scaled, yD_invert);
          Zi = addKeys(C_final, sumXASSET);
        } else if (type == tx_type::XASSET_TRANSFER) {
          Zi = addKeys(sumUSD, sumXASSET);
        } else if (type == tx_type::TRANSFER) {
          Zi = addKeys(sumXHV, sumUSD);
        } else {
          LOG_PRINT_L1("Invalid transaction type specified");
          return false;
        }

        //check Zi == 0
        if (!equalKeys(Zi, zerokey)) {
          LOG_PRINT_L1("Sum check failed (Zi)");
          return false;
        }

        if (bulletproof)
          {
            for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
              proofs.push_back(&rv.p.bulletproofs[i]);
          }
        else
          {
            for (size_t i = 0; i < rv.p.rangeSigs.size(); i++)
              tpool.submit(&waiter, [&, i, offset] { results[i+offset] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]); });
            offset += rv.p.rangeSigs.size();
          }
    
        if (!proofs.empty() && !verBulletproof(proofs))
          {
            LOG_PRINT_L1("Aggregate range proof verified failed");
            return false;
          }
          if (!waiter.wait())
            return false;
      
        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("Range proof verified failed for proof " << i);
            return false;
          }
        }
      
        return true;
      }
    // we can get deep throws from ge_frombytes_vartime if input isn't valid
    catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
        return false;
      }
    catch (...)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
        return false;
      }


/*

        std::vector<const Bulletproof*> bp_proofs;
        std::vector<const BulletproofPlus*> bpp_proofs;
        size_t max_non_bp_proofs = 0, offset = 0;

        for (const rctSig *rvp: rvv)
        {
          CHECK_AND_ASSERT_MES(rvp, false, "rctSig pointer is NULL");
          const rctSig &rv = *rvp;
          CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus,
              false, "verRctSemanticsSimple called on non simple rctSig");
          const bool bulletproof = is_rct_bulletproof(rv.type);
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
          if (bulletproof || bulletproof_plus)
          {
            if (bulletproof_plus)
              CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_plus_amounts(rv.p.bulletproofs_plus), false, "Mismatched sizes of outPk and bulletproofs_plus");
            else
              CHECK_AND_ASSERT_MES(rv.outPk.size() == n_bulletproof_amounts(rv.p.bulletproofs), false, "Mismatched sizes of outPk and bulletproofs");
            if (is_rct_clsag(rv.type))
            {
              CHECK_AND_ASSERT_MES(rv.p.MGs.empty(), false, "MGs are not empty for CLSAG");
              CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.CLSAGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.CLSAGs");
            }
            else
            {
              CHECK_AND_ASSERT_MES(rv.p.CLSAGs.empty(), false, "CLSAGs are not empty for MLSAG");
              CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.p.pseudoOuts and rv.p.MGs");
            }
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.empty(), false, "rv.pseudoOuts is not empty");
          }
          else
          {
            CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.p.rangeSigs.size(), false, "Mismatched sizes of outPk and rv.p.rangeSigs");
            CHECK_AND_ASSERT_MES(rv.pseudoOuts.size() == rv.p.MGs.size(), false, "Mismatched sizes of rv.pseudoOuts and rv.p.MGs");
            CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.empty(), false, "rv.p.pseudoOuts is not empty");
          }
          CHECK_AND_ASSERT_MES(rv.outPk.size() == rv.ecdhInfo.size(), false, "Mismatched sizes of outPk and rv.ecdhInfo");

          if (!bulletproof && !bulletproof_plus)
            max_non_bp_proofs += rv.p.rangeSigs.size();
        }

        results.resize(max_non_bp_proofs);
        for (const rctSig *rvp: rvv)
        {
          const rctSig &rv = *rvp;

          const bool bulletproof = is_rct_bulletproof(rv.type);
          const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
          const keyV &pseudoOuts = bulletproof || bulletproof_plus ? rv.p.pseudoOuts : rv.pseudoOuts;

          rct::keyV masks(rv.outPk.size());
          for (size_t i = 0; i < rv.outPk.size(); i++) {
            masks[i] = rv.outPk[i].mask;
          }
          key sumOutpks = addKeys(masks);
          DP(sumOutpks);
          const key txnFeeKey = scalarmultH(d2h(rv.txnFee));
          addKeys(sumOutpks, txnFeeKey, sumOutpks);

          key sumPseudoOuts = addKeys(pseudoOuts);
          DP(sumPseudoOuts);

          //check pseudoOuts vs Outs..
          if (!equalKeys(sumPseudoOuts, sumOutpks)) {
            LOG_PRINT_L1("Sum check failed");
            return false;
          }

          if (bulletproof_plus)
          {
            for (size_t i = 0; i < rv.p.bulletproofs_plus.size(); i++)
              bpp_proofs.push_back(&rv.p.bulletproofs_plus[i]);
          }
          else if (bulletproof)
          {
            for (size_t i = 0; i < rv.p.bulletproofs.size(); i++)
              bp_proofs.push_back(&rv.p.bulletproofs[i]);
          }
          else
          {
            for (size_t i = 0; i < rv.p.rangeSigs.size(); i++)
              tpool.submit(&waiter, [&, i, offset] { results[i+offset] = verRange(rv.outPk[i].mask, rv.p.rangeSigs[i]); });
            offset += rv.p.rangeSigs.size();
          }
        }
        if (!bpp_proofs.empty() && !verBulletproofPlus(bpp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          if (!waiter.wait())
            return false;
          return false;
        }
        if (!bp_proofs.empty() && !verBulletproof(bp_proofs))
        {
          LOG_PRINT_L1("Aggregate range proof verified failed");
          if (!waiter.wait())
            return false;
          return false;
        }

        if (!waiter.wait())
          return false;
        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("Range proof verified failed for proof " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctSemanticsSimple, but not an actual exception");
        return false;
      }
*/
    }

    //ver RingCT simple
    //assumes only post-rct style inputs (at least for max anonymity)
    bool verRctNonSemanticsSimple(const rctSig & rv) {
      try
      {
        PERF_TIMER(verRctNonSemanticsSimple);

        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit,
            false, "verRctNonSemanticsSimple called on non simple rctSig");
        const bool bulletproof = is_rct_bulletproof(rv.type);
        const bool bulletproof_plus = is_rct_bulletproof_plus(rv.type);
        // semantics check is early, and mixRing/MGs aren't resolved yet
        if (bulletproof || bulletproof_plus)
          CHECK_AND_ASSERT_MES(rv.p.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.p.pseudoOuts and mixRing");
        else
          CHECK_AND_ASSERT_MES(rv.pseudoOuts.size() == rv.mixRing.size(), false, "Mismatched sizes of rv.pseudoOuts and mixRing");

        const size_t threads = std::max(rv.outPk.size(), rv.mixRing.size());

        std::deque<bool> results(threads);
        tools::threadpool& tpool = tools::threadpool::getInstanceForCompute();
        tools::threadpool::waiter waiter(tpool);

        const keyV &pseudoOuts = bulletproof || bulletproof_plus ? rv.p.pseudoOuts : rv.pseudoOuts;

        const key message = get_pre_mlsag_hash(rv, hw::get_device("default"));

        results.clear();
        results.resize(rv.mixRing.size());
        for (size_t i = 0 ; i < rv.mixRing.size() ; i++) {
          tpool.submit(&waiter, [&, i] {
              if (is_rct_clsag(rv.type))
                  results[i] = verRctCLSAGSimple(message, rv.p.CLSAGs[i], rv.mixRing[i], pseudoOuts[i]);
              else
                  results[i] = verRctMGSimple(message, rv.p.MGs[i], rv.mixRing[i], pseudoOuts[i]);
          });
        }
        if (!waiter.wait())
          return false;

        for (size_t i = 0; i < results.size(); ++i) {
          if (!results[i]) {
            LOG_PRINT_L1("verRctMGSimple/verRctCLSAGSimple failed for input " << i);
            return false;
          }
        }

        return true;
      }
      // we can get deep throws from ge_frombytes_vartime if input isn't valid
      catch (const std::exception &e)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple: " << e.what());
        return false;
      }
      catch (...)
      {
        LOG_PRINT_L1("Error in verRctNonSemanticsSimple, but not an actual exception");
        return false;
      }
    }

    //RingCT protocol
    //genRct: 
    //   creates an rctSig with all data necessary to verify the rangeProofs and that the signer owns one of the
    //   columns that are claimed as inputs, and that the sum of inputs  = sum of outputs.
    //   Also contains masked "amount" and "mask" so the receiver can see how much they received
    //verRct:
    //   verifies that all signatures (rangeProogs, MG sig, sum inputs = outputs) are correct
    //decodeRct: (c.f. https://eprint.iacr.org/2015/1098 section 5.1.1)
    //   uses the attached ecdh info to find the amounts represented by each output commitment 
    //   must know the destination private key to find the correct amount, else will return a random number    
    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, key & mask, hw::device &hwdev) {
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeFull, false, "decodeRct called on non-full rctSig");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit);
        mask = ecdh_info.mask;
        key amount = ecdh_info.amount;
        key C = rv.outPk[i].mask;
        DP("C");
        DP(C);
        key Ctmp;
        CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
        CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
        addKeys2(Ctmp, mask, amount, H);
        DP("Ctmp");
        DP(Ctmp);
        if (equalKeys(C, Ctmp) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return h2d(amount);
    }

    xmr_amount decodeRct(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev) {
      key mask;
      return decodeRct(rv, sk, i, mask, hwdev);
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, key &mask, hw::device &hwdev) {
        CHECK_AND_ASSERT_MES(rv.type == RCTTypeSimple || rv.type == RCTTypeBulletproof || rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus || rv.type == RCTTypeSupplyAudit,
            false, "decodeRct called on non simple rctSig");
        CHECK_AND_ASSERT_THROW_MES(i < rv.ecdhInfo.size(), "Bad index");
        CHECK_AND_ASSERT_THROW_MES(rv.outPk.size() == rv.ecdhInfo.size(), "Mismatched sizes of rv.outPk and rv.ecdhInfo");

        //mask amount and mask
        ecdhTuple ecdh_info = rv.ecdhInfo[i];
        hwdev.ecdhDecode(ecdh_info, sk, rv.type == RCTTypeBulletproof2 || rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN || rv.type == RCTTypeHaven2 || rv.type == RCTTypeHaven3 || rv.type == RCTTypeBulletproofPlus|| rv.type == RCTTypeSupplyAudit);
        mask = ecdh_info.mask;
        key amount = ecdh_info.amount;
        key C;
        if (rv.type == RCTTypeCLSAG || rv.type == RCTTypeCLSAGN) {
          if (!equalKeys(rct::identity(),rv.outPk[i].mask)) C = rv.outPk[i].mask;
          else if (!equalKeys(rct::identity(),rv.outPk_usd[i].mask)) C = rv.outPk_usd[i].mask;
          else if ((rv.type == RCTTypeCLSAGN) && (!equalKeys(rct::identity(),rv.outPk_xasset[i].mask))) C = rv.outPk_xasset[i].mask;
          CHECK_AND_ASSERT_THROW_MES(!equalKeys(rct::identity(),C), "warning, bad outPk mask");
        } else {
          CHECK_AND_ASSERT_THROW_MES(!equalKeys(rct::identity(),rv.outPk[i].mask), "warning, bad outPk mask");
          C = rv.outPk[i].mask;
        }
        //key C = rv.outPk[i].mask;
        DP("C");
        DP(C);
        key Ctmp;
        CHECK_AND_ASSERT_THROW_MES(sc_check(mask.bytes) == 0, "warning, bad ECDH mask");
        CHECK_AND_ASSERT_THROW_MES(sc_check(amount.bytes) == 0, "warning, bad ECDH amount");
        addKeys2(Ctmp, mask, amount, H);
        DP("Ctmp");
        DP(Ctmp);
        if (equalKeys(C, Ctmp) == false) {
            CHECK_AND_ASSERT_THROW_MES(false, "warning, amount decoded incorrectly, will be unable to spend");
        }
        return h2d(amount);
    }

    xmr_amount decodeRctSimple(const rctSig & rv, const key & sk, unsigned int i, hw::device &hwdev) {
      key mask;
      return decodeRctSimple(rv, sk, i, mask, hwdev);
    }

  bool checkBurntAndMinted(const rctSig &rv, const xmr_amount amount_burnt, const xmr_amount amount_minted, const offshore::pricing_record pr, const uint64_t& conversion_rate, const std::string& source, const std::string& destination, const uint8_t version) {

    if (version >= HF_VERSION_USE_CONVERSION_RATE) {
      boost::multiprecision::uint128_t burnt_128 = amount_burnt;
      boost::multiprecision::uint128_t conversion_rate_128 = conversion_rate;
      burnt_128 *= conversion_rate_128;
      burnt_128 /= COIN;
      boost::multiprecision::uint128_t minted_128 = amount_minted;
      if (burnt_128 != minted_128) {
        LOG_PRINT_L1("Minted/burnt verification failed");
        return false;
      }
      return true;
    }
    
    if (source == "XHV" && destination == "XUSD") {
      boost::multiprecision::uint128_t xhv_128 = amount_burnt;
      boost::multiprecision::uint128_t exchange_128 = (version >= HF_PER_OUTPUT_UNLOCK_VERSION) ? pr.min("XHV") : pr.ma("XHV");
      boost::multiprecision::uint128_t xusd_128 = xhv_128 * exchange_128;
      xusd_128 /= COIN;
      boost::multiprecision::uint128_t minted_128 = amount_minted;
      if (xusd_128 != minted_128) {
        LOG_PRINT_L1("Minted/burnt verification failed (offshore)");
        return false;
      }
    } else if (source == "XUSD" && destination == "XHV") {
      boost::multiprecision::uint128_t xusd_128 = amount_burnt;
      boost::multiprecision::uint128_t exchange_128 = (version >= HF_PER_OUTPUT_UNLOCK_VERSION) ? pr.max("XHV") : pr.ma("XHV");
      boost::multiprecision::uint128_t xhv_128 = xusd_128 * COIN;
      xhv_128 /= exchange_128;
      boost::multiprecision::uint128_t minted_128 = amount_minted;
      if ((uint64_t)xhv_128 != minted_128) {
        LOG_PRINT_L1("Minted/burnt verification failed (onshore)");
        return false;
      }
    } else if (source == "XUSD" && destination != "XHV" && destination != "XUSD") {
      boost::multiprecision::uint128_t xusd_128 = amount_burnt;
      if (version < HF_VERSION_USE_COLLATERAL) {
        if (version >= HF_VERSION_HAVEN2) {
          xusd_128 -= ((rv.txnOffshoreFee * 4) / 5);
        } else if (version >= HF_VERSION_XASSET_FEES_V2) {
          xusd_128 -= ((rv.txnOffshoreFee_usd * 4) / 5);
        }
      }
      boost::multiprecision::uint128_t exchange_128 = pr[destination];
      boost::multiprecision::uint128_t xasset_128 = xusd_128 * exchange_128;
      xasset_128 /= COIN;
      boost::multiprecision::uint128_t minted_128 = amount_minted;
      if (xasset_128 != minted_128) {
        LOG_PRINT_L1("Minted/burnt verification failed (xusd_to_xasset)");
        return false;
      }
    } else if (source != "XHV" && source != "XUSD" && destination == "XUSD") {
      boost::multiprecision::uint128_t xasset_128 = amount_burnt;
      if (version < HF_VERSION_USE_COLLATERAL) {
        if (version >= HF_VERSION_HAVEN2) {
          xasset_128 -= ((rv.txnOffshoreFee * 4) / 5);
        } else if (version >= HF_VERSION_XASSET_FEES_V2) {
          xasset_128 -= ((rv.txnOffshoreFee_xasset * 4) / 5);
        }
      }
      boost::multiprecision::uint128_t exchange_128 = pr[source];
      boost::multiprecision::uint128_t xusd_128 = xasset_128 * COIN;
      xusd_128 /= exchange_128;
      boost::multiprecision::uint128_t minted_128 = amount_minted;
      if ((uint64_t)xusd_128 != minted_128) {
        LOG_PRINT_L1("Minted/burnt verification failed (xasset_to_xusd)");
        return false;
      }
    } else {
      LOG_PRINT_L1("Invalid request - minted/burnt values only valid for offshore/onshore/xusd_to_xasset/xasset_to_xusd TXs");
      return false;
    }

    // Must have succeeded
    return true;
  }

  //! This function proves that, for a fixed point K in the main subgroup, it holds that K2=r*K, where r is the random number in the output commitment rG+aH
  bool verAmountproof(const rct::AmountProof & amountproof, const keyV & pseudoOuts){

    CHECK_AND_ASSERT_MES(isInMainSubgroup(amountproof.G1), false, "Amount verification failed: G1 is not in the main group");
    CHECK_AND_ASSERT_MES(isInMainSubgroup(amountproof.K1), false, "Amount verification failed: K1 is not in the main group");
    CHECK_AND_ASSERT_MES(isInMainSubgroup(amountproof.H1), false, "Amount verification failed: H1 is not in the main group");
    CHECK_AND_ASSERT_MES(isInMainSubgroup(amountproof.K2), false, "Amount verification failed: K2 is not in the main group");
    CHECK_AND_ASSERT_MES(sc_check(amountproof.sa.bytes) == 0, false, "Amount verification failed: bad scalar s_a");
    CHECK_AND_ASSERT_MES(sc_check(amountproof.sr.bytes) == 0, false, "Amount verification failed: bad scalar s_r");

    const key zerokey = rct::identity();
    const key init_G =  scalarmultBase(d2h(1));
    const key init_H =  scalarmultH(d2h(1));

    // Sum the consumed outputs
    // We do not reuse the value from VerRctSemanticsSimple in order to reduce chances of errors
    
    key sumPseudoOuts = zerokey;
    for (auto po: pseudoOuts) {
      sumPseudoOuts = addKeys(sumPseudoOuts, po);
    }

    keyV challenge_to_hash;
    challenge_to_hash.reserve(6);
    key initKey;
    sc_0(initKey.bytes);
    CHECK_AND_ASSERT_MES(sizeof(initKey.bytes)>=sizeof(config::HASH_KEY_AMOUNTPROOF), false, "Amount proof hash init string is too long");
    memcpy(initKey.bytes,config::HASH_KEY_AMOUNTPROOF,min(sizeof(config::HASH_KEY_AMOUNTPROOF)-1, sizeof(initKey.bytes)-1));
    
    challenge_to_hash.push_back(initKey);
    challenge_to_hash.push_back(amountproof.G1); 
    challenge_to_hash.push_back(amountproof.K1);
    challenge_to_hash.push_back(amountproof.H1);
    challenge_to_hash.push_back(amountproof.K2);
    challenge_to_hash.push_back(sumPseudoOuts);

    
    //Challenge c=H(init, G1, K1, H1,K2, C), which is in practise c=hash(r_r, r_r2, r2, r_a, r. a), see details below on notation 
    const key c=hash_to_scalar(challenge_to_hash);
    
    //First check that sr*G+sa*H==G1+H1+c*C
    //Assuming this holds, we can deduce the following:
    //We know that G1 and H1 are in the main subgroup, and that G and H are generators.
    //Therefore there exist r_r, r_a so that G1=r_r*G and H1=r_a*H
    //From here we derive (using that the hardness of DLP and the fact that c=hash(r_r, r_r2, r2, r_a, r, a)) that:
    //(1) s_r*G==r_r*G+c*r*G
    //(2) s_a*H==r_a*H+c*a*H
    //We can cancel G and H, and derive:
    //(1) s_r==r_r+c*r
    //(2) s_a==r_a+c*a



    key saH = init_H;
    key lhs = init_H;
    key rhs = init_G;
    key cC  = init_H;
    
    scalarmultBase(lhs, amountproof.sr); //lhs=s_r*G
    saH=scalarmultH(amountproof.sa); //saH = s_a*H
    addKeys(lhs, lhs, saH); //lhr=s_r*G+s_a*H

    addKeys(rhs, amountproof.G1, amountproof.H1); //rhs=G1+H1
    cC=scalarmultKey(sumPseudoOuts, c); // cC=c*C
    addKeys(rhs, rhs, cC); //rhs=G1+H1+c+H

    CHECK_AND_ASSERT_MES(equalKeys(lhs, rhs), false, "First check of amount proof verification failed");

    //Second, we check that s_r*K==K1+c*K2
    //Assuming this holds:
    //K1 is also in the main subgroup, so there exists r_r2 so that r_r2*K=K1
    //K2 is also in the main subgroup, so there exists r2 so that r2*K=K2 
    //we know from the first step that s_r==r_r+c*r, therefore
    //r_r*K+c*r*K==K1+c*K2
    //r_r*K+c*r*K==r_r2*K+c*r2*K, now we cancel K
    //
    //r_r+c*r==r_r2+c*r2
    //c=hash(r_r, r_r2, r2, r_a, r, a) 
    //One solution is r_r==r_r2 and r==r2
    //If there is another solution, then we must have a hash collision, which is hard. 
    // we can assume with negligible probability of the being false that
    // 
    //(3) r_r==r_r2
    //(4) r==r2
    //Therefore we have proven that:
    // K2=r*K
    // K1=r_r*K

    lhs=init_H;
    rhs=init_G;

    
    key K; //TO-DO## K definition - must be a hard-coded point, similar like G
    lhs=scalarmultKey(K, amountproof.sr); //lhs = s_r*K
    rhs=scalarmultKey(amountproof.K2, c); //rhs = c*K2
    addKeys(rhs, rhs, amountproof.K1); //rhs = K1+c*K2
    CHECK_AND_ASSERT_MES(equalKeys(lhs, rhs), false, "Second check of amount proof verification failed");


    return true;
  }
}
