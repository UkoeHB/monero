// Copyright (c) 2026, The Monero Project
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

#include <vector>

#include "crypto/crypto.h"
#include "fcmp_pp_types.h"

namespace fcmp_pp
{

/// More useful form of FcmpInputCompressed for use outside `src/fcmp_pp` (e.g. multisig).
struct RerandomizedEnoteKeys final
{
    crypto::public_key O_tilde;
    crypto::public_key I_tilde;
    crypto::public_key R;
    crypto::public_key C_tilde;
};

FcmpInputCompressed rerandomized_enote_keys_to_raw(const RerandomizedEnoteKeys &keys);

/// More useful form of FcmpRerandomizedOutputCompressed for use outside `src/fcmp_pp` (e.g. multisig).
struct RerandomizedEnote final
{
    RerandomizedEnoteKeys keys;
    crypto::secret_key r_o;
    crypto::secret_key r_i;
    crypto::secret_key r_r_i;
    crypto::secret_key r_c;
};

RerandomizedEnote rerandomized_enote_from_parts(
    const crypto::public_key &O,
    const bool use_biased_hash_to_point,
    const crypto::public_key &C,
    const uint8_t r_o[32],
    const uint8_t r_i[32],
    const uint8_t r_r_i[32],
    const uint8_t r_c[32]
);

FcmpRerandomizedOutputCompressed rerandomized_enote_to_raw(const RerandomizedEnote &enote);

////
// Spend Authorization and Linkability Proof (SAL)
//
// There is a Rust FFI layer for making and verifying SAL proofs. This is mainly useful
// for interop with C++-side proof construction (e.g. multisig).
///
struct SalProof final
{
    crypto::public_key P;
    crypto::public_key A;
    crypto::public_key B;
    crypto::public_key R_O;
    crypto::public_key R_P;
    crypto::public_key R_L;
    crypto::ec_scalar s_alpha;
    crypto::ec_scalar s_beta;
    crypto::ec_scalar s_delta;
    crypto::ec_scalar s_y;
    crypto::ec_scalar s_z;
    crypto::ec_scalar s_r_p;
};

std::vector<uint8_t> sal_proof_to_bytes(const SalProof &proof);

} //namespace fcmp_pp
