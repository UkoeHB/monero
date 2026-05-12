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

#include "fcmp_pp_types_interop.h"

#include "fcmp_pp_types.h"
#include "misc_log_ex.h"
#include "prove.h"

#include <cstring>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "fcmp_pp_types_interop"                           \

namespace fcmp_pp
{
//----------------------------------------------------------------------------------------------------------------------
FcmpInputCompressed rerandomized_enote_keys_to_raw(const RerandomizedEnoteKeys &keys)
{
    static_assert(sizeof(FcmpInputCompressed) == sizeof(RerandomizedEnoteKeys));
    FcmpInputCompressed raw{};
    memcpy(&raw, &keys, sizeof(FcmpInputCompressed));
    return raw;
}
//----------------------------------------------------------------------------------------------------------------------
RerandomizedEnote rerandomized_enote_from_parts(
    const crypto::public_key &O,
    const bool use_biased_hash_to_point,
    const crypto::public_key &C,
    const uint8_t r_o[32],
    const uint8_t r_i[32],
    const uint8_t r_r_i[32],
    const uint8_t r_c[32]
){
    RerandomizedEnote rr_enote{};
    memcpy(&rr_enote.r_o, r_o, 32);
    memcpy(&rr_enote.r_i, r_i, 32);
    memcpy(&rr_enote.r_r_i, r_r_i, 32);
    memcpy(&rr_enote.r_c, r_c, 32);
    FcmpInputCompressed compressed = calculate_fcmp_input_for_rerandomizations(
        O,
        C,
        use_biased_hash_to_point,
        rr_enote.r_o,
        rr_enote.r_i,
        rr_enote.r_r_i,
        rr_enote.r_c
    );
    memcpy(&rr_enote.keys.O_tilde, compressed.O_tilde, 32);
    memcpy(&rr_enote.keys.I_tilde, compressed.I_tilde, 32);
    memcpy(&rr_enote.keys.R, compressed.R, 32);
    memcpy(&rr_enote.keys.C_tilde, compressed.C_tilde, 32);

    return rr_enote;
}
//----------------------------------------------------------------------------------------------------------------------
FcmpRerandomizedOutputCompressed rerandomized_enote_to_raw(const RerandomizedEnote &enote)
{
    FcmpRerandomizedOutputCompressed raw{};
    raw.input = rerandomized_enote_keys_to_raw(enote.keys);
    memcpy(&raw.r_o, enote.r_o.data, 32);
    memcpy(&raw.r_i, enote.r_i.data, 32);
    memcpy(&raw.r_r_i, enote.r_r_i.data, 32);
    memcpy(&raw.r_c, enote.r_c.data, 32);
    return raw;
}
//----------------------------------------------------------------------------------------------------------------------
std::vector<uint8_t> sal_proof_to_bytes(const SalProof &proof)
{
    static_assert(sizeof(SalProof) == FCMP_PP_SAL_PROOF_SIZE_V1);
    std::vector<uint8_t> bytes(FCMP_PP_SAL_PROOF_SIZE_V1, 0);
    memcpy(bytes.data(), &proof, FCMP_PP_SAL_PROOF_SIZE_V1);
    return bytes;
}
//----------------------------------------------------------------------------------------------------------------------
} //namespace fcmp_pp
