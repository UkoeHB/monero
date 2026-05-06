// Copyright (c) 2021-2024, The Monero Project
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

//paired header
#include "multisig_sal.h"

//local headers
#include "carrot_core/hash_functions.h"
#include "carrot_core/transcript_fixed.h"
#include "crypto/crypto.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "crypto/generators.h"
#include "misc_language.h"
#include "misc_log_ex.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "fcmp_pp/fcmp_pp_types_interop.h"
#include "fcmp_pp/prove.h"
#include "multisig_tx_builder_ringct.h"
#include "ringct/multiexp.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers
#include <algorithm>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "multisig"

namespace multisig
{
static constexpr const unsigned char SAL_MULTISIG_DOMAIN_SEP_BINONCE_MERGE_FACTOR[] = "SAL multisig binonce merge factor";

//-------------------------------------------------------------------------------------------------------------------
// MuSig2-style bi-nonce signing merge factor
// rho_e = H_n(m, alpha_1_1*U, alpha_2_1*U, ..., alpha_1_N*U, alpha_2_N*U)
//-------------------------------------------------------------------------------------------------------------------
static rct::key multisig_binonce_merge_factor(
    const rct::key &message,
    const rct::keyV &total_alpha_G,
    const rct::keyV &total_alpha_H,
    const rct::keyV &total_alpha_U
){
    static_assert(multisig::signing::kAlphaComponents == 2);
    const auto transcript = carrot::make_fixed_transcript<SAL_MULTISIG_DOMAIN_SEP_BINONCE_MERGE_FACTOR>(
        message,
        total_alpha_G[0],
        total_alpha_G[1],
        total_alpha_H[0],
        total_alpha_H[1],
        total_alpha_U[0],
        total_alpha_U[1]
    );
    rct::key merge_factor;
    carrot::derive_scalar(transcript.data(), transcript.size(), nullptr, merge_factor.bytes);
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(merge_factor.bytes),
        "multisig sal proof: binonce merge factor must be nonzero!");

    return merge_factor;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
void make_sal_multisig_proposal(
    const rct::key &message,
    const rct::key &K,
    const rct::key &kU,
    const crypto::key_image &KI,
    const fcmp_pp::RerandomizedEnote &rr_enote,
    const crypto::secret_key &entropy,
    SalProofMultisigProposal &proposal_out
){
    /// assemble proposal
    proposal_out.message = message;
    proposal_out.K = K;
    proposal_out.kU = kU;
    proposal_out.KI = KI;
    proposal_out.rr_enote = rr_enote;
    proposal_out.entropy = entropy;
}
//-------------------------------------------------------------------------------------------------------------------
// reference: https://github.com/monero-oxide/monero-oxide/blob/fcmp%2B%2B/monero-oxide/ringct/fcmp%2B%2B/src/sal/legacy_multisig.rs
void make_sal_multisig_partial_sig(
    const unsigned char num_signers,
    const SalProofMultisigProposal &proposal,
    const crypto::secret_key &x,
    const crypto::secret_key &y,
    const rct::keyV &total_alpha_G,
    const rct::keyV &total_alpha_H,
    const rct::keyV &total_alpha_U,
    const std::vector<crypto::secret_key> &local_nonce_privkeys,
    SalProofMultisigPartial &partial_sig_out
){
    static_assert(multisig::signing::kAlphaComponents == 2);

    /// input checks and initialization
    CHECK_AND_ASSERT_THROW_MES(!(proposal.K == rct::identity()),
        "make sal multisig partial sig: bad proof key (K identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(proposal.kU == rct::identity()),
        "make sal multisig partial sig: bad proof key (kU identity)!");
    CHECK_AND_ASSERT_THROW_MES(!(rct::ki2rct(proposal.KI) == rct::identity()),
        "make sal multisig partial sig: bad proof key (KI identity)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.entropy)),
        "make sal multisig partial sig: bad entropy (proposal entropy is zero)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(x)),
        "make sal multisig partial sig: bad private key (x zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(x)) == 0,
        "make sal multisig partial sig: bad private key (x)!");
    // CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(y)),
    //     "make sal multisig partial sig: bad private key (y zero)!");  // y can be zero
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(y)) == 0,
        "make sal multisig partial sig: bad private key (y)!");

    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.rr_enote.r_o)),
        "make sal multisig partial sig: bad private key (r_o zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.rr_enote.r_o)) == 0,
        "make sal multisig partial sig: bad private key (r_o)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.rr_enote.r_i)),
        "make sal multisig partial sig: bad private key (r_i zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.rr_enote.r_i)) == 0,
        "make sal multisig partial sig: bad private key (r_i)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.rr_enote.r_r_i)),
        "make sal multisig partial sig: bad private key (r_r_i zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.rr_enote.r_r_i)) == 0,
        "make sal multisig partial sig: bad private key (r_r_i)!");
    CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(proposal.rr_enote.r_c)),
        "make sal multisig partial sig: bad private key (r_c zero)!");
    CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(proposal.rr_enote.r_c)) == 0,
        "make sal multisig partial sig: bad private key (r_c)!");

    CHECK_AND_ASSERT_THROW_MES(local_nonce_privkeys.size() == multisig::signing::kAlphaComponents,
        "make sal multisig partial sig: bad local_nonce_privkeys size!");
    CHECK_AND_ASSERT_THROW_MES(total_alpha_G.size() == multisig::signing::kAlphaComponents,
        "make sal multisig partial sig: bad total_alpha_G size!");
    CHECK_AND_ASSERT_THROW_MES(total_alpha_H.size() == multisig::signing::kAlphaComponents,
        "make sal multisig partial sig: bad total_alpha_H size!");
    CHECK_AND_ASSERT_THROW_MES(total_alpha_U.size() == multisig::signing::kAlphaComponents,
        "make sal multisig partial sig: bad total_alpha_U size!");

    for (size_t i = 0; i < multisig::signing::kAlphaComponents; ++i)
    {
        CHECK_AND_ASSERT_THROW_MES(sc_check(to_bytes(local_nonce_privkeys[i])) == 0,
            "make sal multisig partial sig: bad nonce private key!");
        CHECK_AND_ASSERT_THROW_MES(sc_isnonzero(to_bytes(local_nonce_privkeys[i])),
            "make sal multisig partial sig: nonce private key is zero!");

        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(total_alpha_G[i]),
            "make sal multisig partial sig: total_alpha_G value not in main subgroup!");
        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(total_alpha_H[i]),
            "make sal multisig partial sig: total_alpha_H value not in main subgroup!");
        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(total_alpha_U[i]),
            "make sal multisig partial sig: total_alpha_U value not in main subgroup!");
    }

    // deterministic nonces
    rct::key beta, delta, mu, r_y, r_z_share, r_p, r_r_p;
    carrot::derive_scalar("sal beta", 8, &proposal.entropy, beta.bytes);
    carrot::derive_scalar("sal delta", 9, &proposal.entropy, delta.bytes);
    carrot::derive_scalar("sal mu", 6, &proposal.entropy, mu.bytes);
    carrot::derive_scalar("sal r_y", 7, &proposal.entropy, r_y.bytes);
    carrot::derive_scalar("sal r_z_share", 13, &proposal.entropy, r_z_share.bytes);
    carrot::derive_scalar("sal r_p", 7, &proposal.entropy, r_p.bytes);
    carrot::derive_scalar("sal r_r_p", 9, &proposal.entropy, r_r_p.bytes);

    // r_z is split between signers; instead of dividing by signers to get the share, we start with it and multiply
    // note: r_z = r_i alpha + r_z_base
    rct::key r_z_base = rct::Z;
    r_z_base.bytes[0] = num_signers;
    sc_mul(r_z_base.bytes, r_z_share.bytes, r_z_base.bytes);

    // merge shared nonces
    const rct::key binonce_merge_factor{
        multisig_binonce_merge_factor(proposal.message, total_alpha_G, total_alpha_H, total_alpha_U)
    };

    crypto::secret_key merged_nonce_KI_priv;  //alpha_1_local + rho * alpha_2_local
    sc_muladd(to_bytes(merged_nonce_KI_priv),
        to_bytes(local_nonce_privkeys[1]),
        binonce_merge_factor.bytes,
        to_bytes(local_nonce_privkeys[0]));

    rct::key alpha_G, alpha_H, alpha_U;
    rct::scalarmultKey(alpha_G, total_alpha_G[1], binonce_merge_factor);
    rct::scalarmultKey(alpha_H, total_alpha_H[1], binonce_merge_factor);
    rct::scalarmultKey(alpha_U, total_alpha_U[1], binonce_merge_factor);
    rct::addKeys(alpha_G, alpha_G, total_alpha_G[0]);
    rct::addKeys(alpha_H, alpha_H, total_alpha_H[0]);
    rct::addKeys(alpha_U, alpha_U, total_alpha_U[0]);


    /// build signature
    rct::key T = rct::pk2rct(crypto::get_T());
    rct::key U = rct::pk2rct(crypto::get_U());
    rct::key V = rct::pk2rct(crypto::get_V());
    rct::key L = rct::ki2rct(proposal.KI);
    rct::key xG;
    rct::subKeys(xG, proposal.K, scalarmultKey(T, rct::sk2rct(y)));
    crypto::secret_key y_prime;
    sc_add(to_bytes(y_prime), to_bytes(y), to_bytes(proposal.rr_enote.r_o));

    // R_z = r_i alpha U + r_z_base U
    rct::key R_z{
        rct::addKeys(
            rct::scalarmultKey(alpha_U, rct::sk2rct(proposal.rr_enote.r_i)),
            rct::scalarmultKey(U, r_z_base)
        )
    };

    // P = x G + r_i V + r_i x U + r_p T
    rct::key P{
        rct::addKeys(
            rct::addKeys(
                xG,
                rct::scalarmultKey(V, rct::sk2rct(proposal.rr_enote.r_i))
            ),
            rct::addKeys(
                rct::scalarmultKey(proposal.kU, rct::sk2rct(proposal.rr_enote.r_i)),
                rct::scalarmultKey(T, r_p)
            )
        )
    };

    // A = alpha G + beta V + r_i alpha U + beta x U + delta T
    rct::key A{
        rct::addKeys(
            alpha_G,
            rct::addKeys(
                rct::addKeys(
                    rct::scalarmultKey(V, beta),
                    rct::scalarmultKey(alpha_U, rct::sk2rct(proposal.rr_enote.r_i))
                ),
                rct::addKeys(
                    rct::scalarmultKey(proposal.kU, beta),
                    rct::scalarmultKey(T, delta)
                )
            )
        )
    };

    // B = beta alpha U + mu T
    rct::key B{
        rct::addKeys(
            rct::scalarmultKey(alpha_U, beta),
            rct::scalarmultKey(T, mu)
        )
    };

    // R_O = alpha G + r_y T
    rct::key R_O{
        rct::addKeys(
            alpha_G,
            rct::scalarmultKey(T, r_y)
        )
    };

    // R_P = R_z + r_r_p T
    rct::key R_P{
        rct::addKeys(
            R_z,
            rct::scalarmultKey(T, r_r_p)
        )
    };

    // R_L = alpha_H + r_i alpha U - r_z U
    // R_L = alpha_H + r_i alpha U - (r_i alpha + r_z_base) U
    //     = alpha H - r_z_base U
    rct::key R_L;
    rct::subKeys(R_L, alpha_H, rct::scalarmultKey(U, r_z_base));

    // e = H_n(message, O_tilde, I_tilde, C_tilde, R, L, P, A, B, R_O, R_P, R_L)
    // note: keyed with '0' for compatibility with the rust hash API
    std::vector<rct::key> challenge_data{
        proposal.message,
        rct::pk2rct(proposal.rr_enote.keys.O_tilde),
        rct::pk2rct(proposal.rr_enote.keys.I_tilde),
        rct::pk2rct(proposal.rr_enote.keys.C_tilde),
        rct::pk2rct(proposal.rr_enote.keys.R),
        L, P, A, B, R_O, R_P, R_L
    };
    rct::key e;
    carrot::derive_scalar(challenge_data.data(), 32 * challenge_data.size(), nullptr, e.bytes);

    // s_beta = beta + e * r_i
    crypto::ec_scalar s_beta;
    sc_muladd(to_bytes(s_beta), e.bytes, to_bytes(proposal.rr_enote.r_i), beta.bytes);

    // s_delta = mu + e * delta + e^2 * r_p
    crypto::ec_scalar s_delta;
    sc_muladd(to_bytes(s_delta), e.bytes, delta.bytes, mu.bytes);  //mu + e * delta
    crypto::ec_scalar e_squared;
    sc_mul(to_bytes(e_squared), e.bytes, e.bytes);  //e^2
    sc_muladd(to_bytes(s_delta), to_bytes(e_squared), r_p.bytes, to_bytes(s_delta));  //.. + e^2 * r_p

    // s_y = r_y + e * y'
    crypto::ec_scalar s_y;
    sc_muladd(to_bytes(s_y), e.bytes, to_bytes(y_prime), r_y.bytes);

    // r_p" = r_p - y' - r_r_i
    crypto::secret_key r_p_double_quote;
    sc_sub(to_bytes(r_p_double_quote), r_p.bytes, to_bytes(y_prime));
    sc_sub(to_bytes(r_p_double_quote), to_bytes(r_p_double_quote), to_bytes(proposal.rr_enote.r_r_i));

    // s_r_p = r_r_p + e * r_p"
    crypto::ec_scalar s_r_p;
    sc_muladd(to_bytes(s_r_p), e.bytes, to_bytes(r_p_double_quote), r_r_p.bytes);

    // s_alpha_partial = e * x_share + alpha_share
    crypto::ec_scalar s_alpha_partial;
    sc_muladd(to_bytes(s_alpha_partial), e.bytes, to_bytes(x), to_bytes(merged_nonce_KI_priv));

    // s_z_partial = r_z * (1/num_signers) + r_i * s_alpha_partial
    crypto::ec_scalar s_z_partial;
    sc_muladd(to_bytes(s_z_partial), to_bytes(s_alpha_partial), to_bytes(proposal.rr_enote.r_i), r_z_share.bytes);

    // save result
    fcmp_pp::SalProof partial_proof{
        .P = rct::rct2pk(P),
        .A = rct::rct2pk(A),
        .B = rct::rct2pk(B),
        .R_O = rct::rct2pk(R_O),
        .R_P = rct::rct2pk(R_P),
        .R_L = rct::rct2pk(R_L),
        .s_alpha = s_alpha_partial,
        .s_beta = s_beta,
        .s_delta = s_delta,
        .s_y = s_y,
        .s_z = s_z_partial,
        .s_r_p = s_r_p,
    };
    partial_sig_out = SalProofMultisigPartial{
        .message = proposal.message,
        .K = proposal.K,
        .KI = proposal.KI,
        .rr_enote_keys = proposal.rr_enote.keys,
        .partial_proof = partial_proof
    };
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_sal_multisig_proof(
    const std::vector<SalProofMultisigPartial> &partial_sigs,
    fcmp_pp::SalProof &proof_out
){
    // input checks
    CHECK_AND_ASSERT_THROW_MES(partial_sigs.size() > 0,
        "finalize sal multisig proof: no partial signatures to make a proof out of!");

    // common parts between partial signatures should match
    for (const SalProofMultisigPartial &partial_sig : partial_sigs)
    {
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].message == partial_sig.message,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].K == partial_sig.K,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].KI == partial_sig.KI,
            "finalize sal multisig proof: input partial sigs don't match!");

        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.P == partial_sig.partial_proof.P,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.A == partial_sig.partial_proof.A,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.B == partial_sig.partial_proof.B,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.R_O == partial_sig.partial_proof.R_O,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.R_P == partial_sig.partial_proof.R_P,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.R_L == partial_sig.partial_proof.R_L,
            "finalize sal multisig proof: input partial sigs don't match!");
        // CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_alpha == partial_sig.partial_proof.s_alpha,
        //     "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_beta == partial_sig.partial_proof.s_beta,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_delta == partial_sig.partial_proof.s_delta,
            "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_y == partial_sig.partial_proof.s_y,
            "finalize sal multisig proof: input partial sigs don't match!");
        // CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_z == partial_sig.partial_proof.s_z,
        //     "finalize sal multisig proof: input partial sigs don't match!");
        CHECK_AND_ASSERT_THROW_MES(partial_sigs[0].partial_proof.s_r_p == partial_sig.partial_proof.s_r_p,
            "finalize sal multisig proof: input partial sigs don't match!");
    }


    // assemble the final proof
    crypto::ec_scalar s_alpha, s_z;
    memcpy(s_alpha.data, rct::zero().bytes, 32);
    memcpy(s_z.data, rct::zero().bytes, 32);
    for (const SalProofMultisigPartial &partial_sig : partial_sigs)
    {
        sc_add(to_bytes(s_alpha), to_bytes(s_alpha), to_bytes(partial_sig.partial_proof.s_alpha));
        sc_add(to_bytes(s_z), to_bytes(s_z), to_bytes(partial_sig.partial_proof.s_z));
    }

    proof_out = partial_sigs[0].partial_proof;
    proof_out.s_alpha = s_alpha;
    proof_out.s_z = s_z;

    // verify that proof assembly succeeded

    // 1. C++ impl
    CHECK_AND_ASSERT_THROW_MES(
        verify_sal_proof(
            partial_sigs[0].message,
            partial_sigs[0].rr_enote_keys,
            partial_sigs[0].KI,
            proof_out
        ),
        "finalize sal multisig proof: proof failed to verify on assembly (c++)!");

    // 2. Rust impl
    FcmpInputCompressed raw_enote_keys = rerandomized_enote_keys_to_raw(partial_sigs[0].rr_enote_keys);
    fcmp_pp::FcmpPpSalProof raw_proof = sal_proof_to_bytes(proof_out);
    CHECK_AND_ASSERT_THROW_MES(
        fcmp_pp::verify_sal(
            rct::rct2hash(partial_sigs[0].message),
            raw_enote_keys,
            partial_sigs[0].KI,
            raw_proof
        ),
        "finalize sal multisig proof: proof failed to verify on assembly (rust)!");
}
//-------------------------------------------------------------------------------------------------------------------
bool verify_sal_proof(
    const rct::key &message,
    const fcmp_pp::RerandomizedEnoteKeys &keys,
    const crypto::key_image &KI,
    const fcmp_pp::SalProof &proof
){
    std::vector<rct::MultiexpData> data1{}, data2{};

    const rct::key O_tilde = rct::pk2rct(keys.O_tilde);
    const rct::key I_tilde = rct::pk2rct(keys.I_tilde);
    const rct::key C_tilde = rct::pk2rct(keys.C_tilde);
    const rct::key R = rct::pk2rct(keys.R);
    const rct::key L = rct::ki2rct(KI);
    const rct::key P = rct::pk2rct(proof.P);
    const rct::key A = rct::pk2rct(proof.A);
    const rct::key B = rct::pk2rct(proof.B);
    const rct::key R_O = rct::pk2rct(proof.R_O);
    const rct::key R_P = rct::pk2rct(proof.R_P);
    const rct::key R_L = rct::pk2rct(proof.R_L);

    const rct::key s_alpha = *(rct::key*)&proof.s_alpha;
    const rct::key s_beta = *(rct::key*)&proof.s_beta;
    const rct::key s_delta = *(rct::key*)&proof.s_delta;
    const rct::key s_y = *(rct::key*)&proof.s_y;
    const rct::key s_z = *(rct::key*)&proof.s_z;
    const rct::key s_r_p = *(rct::key*)&proof.s_r_p;

    const rct::key G = rct::G;
    const rct::key V = rct::pk2rct(crypto::get_V());
    const rct::key U = rct::pk2rct(crypto::get_U());
    const rct::key T = rct::pk2rct(crypto::get_T());

    // e = H_n(message, O_tilde, I_tilde, C_tilde, R, L, P, A, B, R_O, R_P, R_L)
    std::vector<rct::key> challenge_data{message, O_tilde, I_tilde, C_tilde, R, L, P, A, B, R_O, R_P, R_L};
    rct::key e;
    carrot::derive_scalar(challenge_data.data(), 32 * challenge_data.size(), nullptr, e.bytes);

    // BP+ check
    // e^2 P + e A + B == s_alpha e G + s_beta e V + s_alpha s_beta U + s_delta T
    rct::key e_squared;
    sc_mul(e_squared.bytes, e.bytes, e.bytes);
    rct::key s_alpha_e;
    sc_mul(s_alpha_e.bytes, e.bytes, s_alpha.bytes);
    rct::key s_beta_e;
    sc_mul(s_beta_e.bytes, e.bytes, s_beta.bytes);
    rct::key s_alpha_beta;
    sc_mul(s_alpha_beta.bytes, s_alpha.bytes, s_beta.bytes);

    data1.emplace_back(e_squared, P);
    data1.emplace_back(e, A);
    data1.emplace_back(rct::I, B);
    // ==
    data2.emplace_back(s_alpha_e, G);
    data2.emplace_back(s_beta_e, V);
    data2.emplace_back(s_alpha_beta, U);
    data2.emplace_back(s_delta, T);

    if (rct::straus(data1, NULL, 0) != rct::straus(data2, NULL, 0))
    {
        MERROR("sal proof validation failure (BP+ check)");
        return false;
    }
    data1.clear();
    data2.clear();

    // O_tilde check
    // R_O + e O_tilde == s_alpha G + s_y T
    data1.emplace_back(rct::I, R_O);
    data1.emplace_back(e, O_tilde);
    // ==
    data2.emplace_back(s_alpha, G);
    data2.emplace_back(s_y, T);

    if (rct::straus(data1, NULL, 0) != rct::straus(data2, NULL, 0))
    {
        MERROR("sal proof validation failure (O_tilde check)");
        return false;
    }
    data1.clear();
    data2.clear();

    // P' check
    // R_P + e * (P - O_tilde - R)) == s_z U + s_r_p T
    rct::key P_subs;
    rct::subKeys(P_subs, P, O_tilde);
    rct::subKeys(P_subs, P_subs, R);

    data1.emplace_back(rct::I, R_P);
    data1.emplace_back(e, P_subs);
    // ==
    data2.emplace_back(s_z, U);
    data2.emplace_back(s_r_p, T);

    if (rct::straus(data1, NULL, 0) != rct::straus(data2, NULL, 0))
    {
        MERROR("sal proof validation failure (P' check)");
        return false;
    }
    data1.clear();
    data2.clear();

    // L check
    // R_L + e L == s_alpha I_tilde - s_z U
    rct::key s_z_negative;
    sc_sub(s_z_negative.bytes, rct::Z.bytes, s_z.bytes);

    data1.emplace_back(rct::I, R_L);
    data1.emplace_back(e, L);
    // ==
    data2.emplace_back(s_alpha, I_tilde);
    data2.emplace_back(s_z_negative, U);

    if (rct::straus(data1, NULL, 0) != rct::straus(data2, NULL, 0))
    {
        MERROR("sal proof validation failure (L check)");
        return false;
    }

    return true;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace multisig
