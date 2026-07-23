// Copyright (c) 2025, The Monero Project
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
#include "tx_builder_multisig.h"

//local headers
#include "carrot_core/output_set_finalization.h"
#include "carrot_impl/address_utils.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_impl/tx_proposal.h"
#include "common/apply_permutation.h"
#include "crypto/generators.h"
#include "fcmp_pp/fcmp_pp_types_interop.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "fcmp_pp/prove.h"
#include "misc_log_ex.h"
#include "multisig/multisig.h"
#include "multisig/multisig_sal.h"
#include "multisig/multisig_tx_builder_ringct.h"
#include "ringct/rctOps.h"
#include "tx_builder.h"
#include "wallet2_basic/wallet2_types.h"

//third party headers

//standard headers
#include <algorithm>
#include <variant>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.tx_builder_multisig"

namespace tools
{
namespace wallet
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void get_sorted_key_images(const std::vector<crypto::key_image> &key_images,
    std::vector<crypto::key_image> &sorted_key_images_out,
    std::vector<std::size_t> &order_out)
{
    size_t num_ki = key_images.size();
    sorted_key_images_out.clear();
    sorted_key_images_out.reserve(num_ki);
    order_out.clear();
    order_out.reserve(num_ki);

    // derive key images
    std::vector<std::pair<crypto::key_image, std::size_t>> sortable_data;
    sortable_data.reserve(num_ki);
    for (std::size_t i = 0; i < num_ki; ++i)
        sortable_data.emplace_back(key_images.at(i), i);

    // sort key images
    std::sort(sortable_data.begin(), sortable_data.end(), std::greater{});

    // collect result
    for (const auto &p : sortable_data)
    {
        sorted_key_images_out.push_back(p.first);
        order_out.push_back(p.second);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// NOTE: Only supports legacy multisig, where subaddress extensions are additive and
// keys are shared on `G` while `T` is a placeholder.
static void prepare_legacy_multisig_input_signing_attempt(
    const carrot::OutputOpeningHintVariant &opening_hint,
    const std::unordered_set<crypto::public_key> &ignore_set,
    // Should only include 'active' signers, and `ignore_set` excludes active signers referenced here.
    const std::vector<wallet2_basic::multisig_info> &multisig_infos,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const size_t threshold,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    std::unordered_set<rct::key> &all_used_L_inout,
    std::vector<rct::key> &used_L_out,
    std::vector<crypto::secret_key> &local_alpha_out,
    rct::keyV &alpha_G_out,
    rct::keyV &alpha_H_out,
    rct::keyV &alpha_U_out,
    crypto::key_image &key_image_out,
    rct::key &kU_out,
    // Subaddress extension + sender extension
    crypto::secret_key &onetime_address_extension_g_out,
    crypto::secret_key &onetime_address_extension_t_out)
{
    used_L_out.clear();
    local_alpha_out.clear();
    alpha_G_out.clear();
    alpha_H_out.clear();
    alpha_U_out.clear();

    crypto::secret_key subaddress_extention_g;
    crypto::secret_key _subaddress_scalar;
    addr_dev.get_address_openings(subaddress_index_ref(opening_hint), subaddress_extention_g, _subaddress_scalar);

    // k^j_g = k_g * k^j_subscal + k^j_subext
    // crypto::secret_key address_privkey_g;
    // sc_muladd(to_bytes(address_privkey_g), to_bytes(k_privkey_g),
    //     to_bytes(subaddress_scalar), to_bytes(subaddress_extention_g));

    // k^j_t = k_t * k^j_subscal
    //sc_mul(to_bytes(address_privkey_t), to_bytes(k_privkey_t), to_bytes(subaddress_scalar));

    // scan k^g_o, k^t_o
    crypto::public_key _main_address_spend_pubkeys[2];
    crypto::secret_key sender_extension_g;
    crypto::secret_key sender_extension_t;
    CHECK_AND_ASSERT_THROW_MES(carrot::try_scan_opening_hint_sender_extensions(opening_hint,
            carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),
            k_view_incoming_dev,
            s_view_balance_dev,
            sender_extension_g,
            sender_extension_t),
        "multisig composite keys for signing init: failed computing sender extensions");

    // Extensions
    sc_add(to_bytes(onetime_address_extension_g_out),
        to_bytes(subaddress_extention_g),
        to_bytes(sender_extension_g));
    onetime_address_extension_t_out = sender_extension_t;

    // Aggregate keys
    {
        const crypto::public_key &onetime_address = onetime_address_ref(opening_hint);

        // Local nonces
        local_alpha_out.reserve(multisig::signing::kAlphaComponents);
        alpha_G_out.reserve(multisig::signing::kAlphaComponents);
        alpha_H_out.reserve(multisig::signing::kAlphaComponents);
        alpha_U_out.reserve(multisig::signing::kAlphaComponents);

        for (size_t n = 0; n < multisig::signing::kAlphaComponents; ++n)
        {
            crypto::secret_key a = rct::rct2sk(rct::skGen());
            local_alpha_out.push_back(a);

            multisig::generate_multisig_nonces(
                use_biased_hash_to_point(opening_hint),
                onetime_address,
                a,
                (crypto::public_key&)alpha_G_out.emplace_back(),
                (crypto::public_key&)alpha_H_out.emplace_back(),
                (crypto::public_key&)alpha_U_out.emplace_back()
            );
        }

        // Extension
        crypto::ec_point key_image_generator;
        crypto::derive_key_image_generator(onetime_address,
            use_biased_hash_to_point(opening_hint),
            key_image_generator);
        rct::key ki_gen = rct::pt2rct(key_image_generator);
        rct::key U = rct::pk2rct(crypto::get_U());

        rct::key ki = rct::scalarmultKey(ki_gen, rct::sk2rct(onetime_address_extension_g_out));
        rct::key kU = rct::scalarmultKey(U, rct::sk2rct(onetime_address_extension_g_out));

        // Local keys
        // note: used kU is not needed because we assume partial ki and kU are aligned in multisig_info
        std::unordered_set<crypto::key_image> used_ki{};
        for (const crypto::secret_key &k : local_multisig_keys)
        {
            rct::key pki = rct::scalarmultKey(rct::pt2rct(key_image_generator), rct::sk2rct(k));
            rct::key kU_temp = rct::scalarmultKey(U, rct::sk2rct(k));

            rct::addKeys(ki, ki, pki);
            rct::addKeys(kU, kU, kU_temp);
            used_ki.insert(rct::rct2ki(pki));
        }

        // Other signers' keys
        size_t n_signers_used = 1;
        for (const auto &multisig_info : multisig_infos)
        {
            // Ignored signers
            if (ignore_set.find(multisig_info.m_signer) != ignore_set.end())
                continue;
            ++n_signers_used;

            // Save nonces
            for (size_t n = 0; n < multisig::signing::kAlphaComponents; ++n)
            {
                for (const auto &lr: multisig_info.m_LR)
                {
                    if (all_used_L_inout.find(lr.m_L) != all_used_L_inout.end())
                        continue;
                    all_used_L_inout.insert(lr.m_L);
                    used_L_out.push_back(lr.m_L);
                    rct::addKeys(alpha_G_out[n], alpha_G_out[n], lr.m_L);
                    rct::addKeys(alpha_H_out[n], alpha_H_out[n], lr.m_R);
                    rct::addKeys(alpha_U_out[n], alpha_U_out[n], lr.m_U);
                    break;
                }
            }

            // Add ki and kU shares
            size_t key_clamp = std::min(multisig_info.m_partial_key_images.size(), multisig_info.m_partial_kU.size());
            for (size_t i = 0; i < key_clamp; ++i)
            {
                if (used_ki.find(multisig_info.m_partial_key_images.at(i)) != used_ki.end())
                    continue;
                rct::addKeys(ki, ki, rct::ki2rct(multisig_info.m_partial_key_images.at(i)));
                rct::addKeys(kU, kU, rct::pk2rct(multisig_info.m_partial_kU.at(i)));
                used_ki.insert(multisig_info.m_partial_key_images.at(i));
            }
        }

        CHECK_AND_ASSERT_THROW_MES(n_signers_used >= threshold, "LR not found for enough participants");

        key_image_out = rct::rct2ki(ki);
        kU_out = kU;
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static bool multisig_selfsends_are_owned(const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const carrot::address_device &addr_dev)
{
    for (const auto &selfsend : tx_proposal.selfsend_payment_proposals)
    {
        crypto::public_key nominal_address_spend_pubkey;
        addr_dev.get_address_spend_pubkey(selfsend.subaddr_index, nominal_address_spend_pubkey);

        if (nominal_address_spend_pubkey != selfsend.destination_address_spend_pubkey)
            return false;
    }
    return true;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// Selects one non-zero value `a` from `multisig_nonces_inout` such that `!used_L.contains(a G)`.
// Sets `a` in `multisig_nonces_inout` to zero if found.
static bool get_multisig_nonce(
    const std::vector<rct::key> &used_L,
    std::vector<rct::key> *multisig_nonces_inout,
    crypto::secret_key &nonce_out)
{
    if (multisig_nonces_inout == nullptr)
        return false;

    for (auto &a : *multisig_nonces_inout)
    {
        if (a == rct::zero())
            continue;

        // decide whether or not to return a nonce just based on if its pubkey 'L = k*G' is used by a tx attempt
        rct::key L;
        rct::scalarmultBase(L, a);
        if (std::find(used_L.cbegin(), used_L.cend(), L) != used_L.cend())
        {
            nonce_out = rct::rct2sk(a);
            memwipe(static_cast<rct::key *>(&a), sizeof(rct::key));  //CRITICAL: a nonce may only be used once!
            return true;
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static cryptonote::transaction finalize_multisig_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<std::vector<crypto::secret_key>> &multisig_enote_rr,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &key_images,
    // A partial sig for each input. These should each be 'complete'.
    const std::vector<multisig::SalProofMultisigPartial> &saved_partial_sigs)
{
    size_t num_inputs = tx_proposal.input_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(num_inputs == key_images.size(),
        "finalize multisig tx: num inputs != num key images");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == saved_partial_sigs.size(),
        "finalize multisig tx: num inputs != num saved partial sigs");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == multisig_enote_rr.size(),
        "sign multisig partial tx: num input proposals != num rerandomization sets");

    std::vector<crypto::key_image> key_images_sorted;
    std::vector<std::size_t> key_image_order;
    get_sorted_key_images(key_images, key_images_sorted, key_image_order);

    // Collect output enote proposals
    // NOTE: we assume this validates that selfsend output proposals are in fact owned by the multisig account
    crypto::public_key _main_address_spend_pubkeys[2];
    std::vector<fcmp_pp::OutputPair> output_pairs;
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals;
    carrot::encrypted_payment_id_t encrypted_payment_id;
    std::vector<FcmpRerandomizedOutputCompressed> _rerandomized_outputs;
    std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> _rerandomized_outputs_by_ota;
    prepare_for_fcmp_pp_proofs(
        tx_proposal,
        carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),
        *k_view_incoming_dev,
        s_view_balance_dev,
        key_images_sorted,
        output_pairs,
        output_enote_proposals,
        encrypted_payment_id,
        _rerandomized_outputs,
        _rerandomized_outputs_by_ota
    );

    // Recover rerandomized outputs
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
    rerandomized_outputs.reserve(num_inputs);

    for (size_t i = 0; i < num_inputs; ++i)
    {
        const carrot::InputProposalV1 &input_proposal = tx_proposal.input_proposals.at(i);
        const auto &rr_vec = multisig_enote_rr.at(i);
        CHECK_AND_ASSERT_THROW_MES(rr_vec.size() == 4,
            "sign multisig partial tx: invalid rerandomization set (wrong size)");

        auto &rerandomized_output = rerandomized_outputs.emplace_back();
        rerandomized_output.input = fcmp_pp::calculate_fcmp_input_for_rerandomizations(
            onetime_address_ref(input_proposal),
            amount_commitment_ref(input_proposal),
            use_biased_hash_to_point(input_proposal),
            rr_vec[0],
            rr_vec[1],
            rr_vec[2],
            rr_vec[3]
        );

        memcpy(rerandomized_output.r_o, to_bytes(rr_vec[0]), 32);
        memcpy(rerandomized_output.r_i, to_bytes(rr_vec[1]), 32);
        memcpy(rerandomized_output.r_r_i, to_bytes(rr_vec[2]), 32);
        memcpy(rerandomized_output.r_c, to_bytes(rr_vec[3]), 32);
    }

    // Finalize sal proofs
    std::vector<fcmp_pp::SalProof> sal_proofs;
    sal_proofs.reserve(num_inputs);

    for (size_t i = 0; i < num_inputs; ++i)
        multisig::finalize_sal_multisig_proof({saved_partial_sigs[i]}, sal_proofs.emplace_back());

    // Align everything with sorted key images
    std::vector<fcmp_pp::FcmpPpSalProof> sorted_sal_proofs;
    sorted_sal_proofs.reserve(sal_proofs.size());
    for (const auto &sal_proof : sal_proofs)
        sorted_sal_proofs.emplace_back(fcmp_pp::sal_proof_to_bytes(sal_proof));
    tools::apply_permutation(key_image_order, rerandomized_outputs);
    tools::apply_permutation(key_image_order, output_pairs);
    tools::apply_permutation(key_image_order, sorted_sal_proofs);

    return finalize_fcmps_and_range_proofs(key_images_sorted,
        rerandomized_outputs,
        output_pairs,
        sorted_sal_proofs,
        output_enote_proposals,
        encrypted_payment_id,
        tx_proposal.fee,
        tree_cache,
        curve_trees);
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// NOTE: Only supports legacy multisig, where subaddress extensions are additive and
// keys are shared on `G` while `T` is a placeholder.
void get_multisig_key_image_from_opening_hint(
    const carrot::OutputOpeningHintVariant &opening_hint,
    const std::vector<wallet2_basic::multisig_info> &multisig_infos,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    crypto::key_image &key_image_out)
{
    crypto::secret_key subaddress_extention_g;
    crypto::secret_key _subaddress_scalar;
    addr_dev.get_address_openings(subaddress_index_ref(opening_hint), subaddress_extention_g, _subaddress_scalar);

    // k^j_g = k_g * k^j_subscal + k^j_subext
    // crypto::secret_key address_privkey_g;
    // sc_muladd(to_bytes(address_privkey_g), to_bytes(k_privkey_g),
    //     to_bytes(subaddress_scalar), to_bytes(subaddress_extention_g));

    // k^j_t = k_t * k^j_subscal
    //sc_mul(to_bytes(address_privkey_t), to_bytes(k_privkey_t), to_bytes(subaddress_scalar));

    // scan k^g_o, k^t_o
    crypto::public_key _main_address_spend_pubkeys[2];
    crypto::secret_key sender_extension_g;
    crypto::secret_key _sender_extension_t;
    CHECK_AND_ASSERT_THROW_MES(carrot::try_scan_opening_hint_sender_extensions(opening_hint,
            carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),
            k_view_incoming_dev,
            s_view_balance_dev,
            sender_extension_g,
            _sender_extension_t),
        "multisig composite keys for signing init: failed computing sender extensions");

    // Extensions
    crypto::secret_key onetime_address_extension_g;
    sc_add(to_bytes(onetime_address_extension_g),
        to_bytes(subaddress_extention_g),
        to_bytes(sender_extension_g));

    // Extension to KI
    const crypto::public_key &onetime_address = onetime_address_ref(opening_hint);
    crypto::ec_point key_image_generator;
    crypto::derive_key_image_generator(onetime_address,
        use_biased_hash_to_point(opening_hint),
        key_image_generator);
    rct::key ki_gen = rct::pt2rct(key_image_generator);

    rct::key ki = rct::scalarmultKey(ki_gen, rct::sk2rct(onetime_address_extension_g));

    // Local keys
    std::unordered_set<crypto::key_image> used_ki{};
    for (const crypto::secret_key &k : local_multisig_keys)
    {
        rct::key pki = rct::scalarmultKey(ki_gen, rct::sk2rct(k));

        rct::addKeys(ki, ki, pki);
        used_ki.insert(rct::rct2ki(pki));
    }

    // Other signers' keys
    for (const auto& multisig_info : multisig_infos)
    {
        // Add ki shares
        for (size_t i = 0; i < multisig_info.m_partial_key_images.size(); ++i)
        {
            if (used_ki.find(multisig_info.m_partial_key_images.at(i)) != used_ki.end())
                continue;
            rct::addKeys(ki, ki, rct::ki2rct(multisig_info.m_partial_key_images.at(i)));
            used_ki.insert(multisig_info.m_partial_key_images.at(i));
        }
    }

    key_image_out = rct::rct2ki(ki);
}
//-------------------------------------------------------------------------------------------------------------------
pending_tx tx_proposal_to_multisig_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<std::unordered_set<crypto::public_key>> &ignore_sets,
    const std::vector<const std::vector<wallet2_basic::multisig_info>*> &multisig_infos,
    const size_t threshold,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &expected_key_images,
    std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs_out)
{
    saved_partial_sigs_out.clear();

    // Checks
    size_t num_signing_attempts = ignore_sets.size();
    size_t num_inputs = tx_proposal.input_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(num_inputs > 0,
        "tx proposal to multisig pending tx: no inputs");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == multisig_infos.size(),
        "tx proposal to multisig pending tx: invalid number of multisig infos");

    CHECK_AND_ASSERT_THROW_MES(multisig_selfsends_are_owned(tx_proposal, addr_dev),
        "tx proposal to multisig pending tx: failed checking selfsend is owned by this multisig account");

    std::vector<crypto::key_image> expected_key_images_sorted = expected_key_images;
    std::sort(expected_key_images_sorted.begin(), expected_key_images_sorted.end(), std::greater{});

    // Rerandomization factors for each input
    crypto::public_key _main_address_spend_pubkeys[2];
    std::vector<fcmp_pp::OutputPair> _output_pairs;
    std::vector<carrot::RCTOutputEnoteProposal> _output_enote_proposals;
    carrot::encrypted_payment_id_t _encrypted_payment_id;
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs;
    std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> _rerandomized_outputs_by_ota;
    prepare_for_fcmp_pp_proofs(
        tx_proposal,
        carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),
        k_view_incoming_dev,
        s_view_balance_dev,
        expected_key_images_sorted,
        _output_pairs,
        _output_enote_proposals,
        _encrypted_payment_id,
        rerandomized_outputs,
        _rerandomized_outputs_by_ota
    );

    std::vector<std::vector<crypto::secret_key>> multisig_enote_rr;
    multisig_enote_rr.reserve(rerandomized_outputs.size());
    for (const FcmpRerandomizedOutputCompressed &rr_enote : rerandomized_outputs)
    {
        multisig_enote_rr.emplace_back(std::vector<crypto::secret_key>{
            (const crypto::secret_key&)rr_enote.r_o,
            (const crypto::secret_key&)rr_enote.r_i,
            (const crypto::secret_key&)rr_enote.r_r_i,
            (const crypto::secret_key&)rr_enote.r_c,
        });
    }

    // Local signing keys used
    std::unordered_set<crypto::public_key> signing_keys;
    signing_keys.reserve(local_multisig_keys.size());
    crypto::secret_key aggregate_local_k = crypto::null_skey;

    for (const crypto::secret_key &k : local_multisig_keys)
    {
        sc_add(to_bytes(aggregate_local_k), to_bytes(aggregate_local_k), to_bytes(k));

        crypto::public_key pkey;
        CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, pkey), "Failed to derive public key");
        signing_keys.insert(pkey);
    }

    // Message to sign
    crypto::hash signable_message;
    carrot::make_signable_tx_hash_from_proposal_v1(tx_proposal,
        s_view_balance_dev,
        &k_view_incoming_dev,
        expected_key_images_sorted,
        signable_message);

    // Signing attempts
    std::vector<multisig_sig> multisig_sigs;
    std::unordered_set<rct::key> all_used_L{};
    multisig_sigs.reserve(num_signing_attempts);

    for (size_t s = 0; s < num_signing_attempts; ++s)
    {
        auto &partial_sigs = saved_partial_sigs_out.emplace_back();

        std::vector<crypto::key_image> attempt_key_images;
        std::vector<rct::key> attempt_kU;
        std::vector<rct::key> used_L;
        rct::keyM total_alpha_G;
        rct::keyM total_alpha_H;
        rct::keyM total_alpha_U;
        rct::keyV all_s_alpha;
        rct::keyV all_s_z;
        attempt_key_images.reserve(num_inputs);
        attempt_kU.reserve(num_inputs);
        used_L.reserve(num_inputs);
        total_alpha_G.reserve(num_inputs);
        total_alpha_H.reserve(num_inputs);
        total_alpha_U.reserve(num_inputs);
        all_s_alpha.reserve(num_inputs);
        all_s_z.reserve(num_inputs);

        for (size_t i = 0; i < num_inputs; ++i)
        {
            const auto &input_proposal = tx_proposal.input_proposals.at(i);

            // Prep
            std::vector<crypto::secret_key> local_alpha;
            rct::keyV alpha_G;
            rct::keyV alpha_H;
            rct::keyV alpha_U;

            crypto::key_image key_image;
            rct::key kU;
            crypto::secret_key onetime_address_extension_g;
            crypto::secret_key onetime_address_extension_t;
            prepare_legacy_multisig_input_signing_attempt(
                input_proposal,
                ignore_sets.at(s),
                *multisig_infos.at(i),
                local_multisig_keys,
                threshold,
                addr_dev,
                &k_view_incoming_dev,
                s_view_balance_dev,
                all_used_L,
                used_L,
                local_alpha,
                alpha_G,
                alpha_H,
                alpha_U,
                key_image,
                kU,
                onetime_address_extension_g,
                onetime_address_extension_t);

            total_alpha_G.push_back(alpha_G);
            total_alpha_H.push_back(alpha_H);
            total_alpha_U.push_back(alpha_U);
            attempt_key_images.push_back(key_image);
            attempt_kU.push_back(kU);

            // Proposal
            multisig::SalProofMultisigProposal proposal;
            multisig::make_sal_multisig_proposal(
                rct::hash2rct(signable_message),
                rct::pk2rct(onetime_address_ref(input_proposal)),
                kU,
                key_image,
                fcmp_pp::rerandomized_enote_from_raw(rerandomized_outputs.at(i)),
                proposal
            );

            // Partial signature
            crypto::secret_key x;
            sc_add(to_bytes(x), to_bytes(aggregate_local_k), to_bytes(onetime_address_extension_g));
            crypto::secret_key y = onetime_address_extension_t;

            multisig::SalProofMultisigPartial partial_sig;
            multisig::make_sal_multisig_partial_sig(
                (const unsigned char)threshold,
                proposal,
                x,
                y,
                alpha_G,
                alpha_H,
                alpha_U,
                local_alpha,
                partial_sig
            );

            all_s_alpha.push_back((const rct::key&)partial_sig.partial_proof.s_alpha);
            all_s_z.push_back((const rct::key&)partial_sig.partial_proof.s_z);

            // Save in case of threshold == 1
            partial_sigs.push_back(partial_sig);
        }

        // Check collected key images
        if (attempt_key_images != expected_key_images)
        {
            // TODO: validate key image shares on receipt
            MERROR("tx proposal to multisig pending tx: skipping attempt, signer subset key images don't \
                match expected key images (there may be a malicious/buggy participant who provided invalid \
                key image shares)");
            continue;
        }

        multisig_sigs.push_back({
            .ignore = ignore_sets.at(s),
            .used_L = used_L,
            .signing_keys = signing_keys,
            .total_alpha_G = total_alpha_G,
            .total_alpha_H = total_alpha_H,
            .total_alpha_U = total_alpha_U,
            .total_kU = attempt_kU,
            .c_0 = all_s_z,
            .s = all_s_alpha,
        });
    }

    // General pending_tx setup
    pending_tx ptx = make_pending_carrot_tx(tx_proposal,
        expected_key_images_sorted,
        k_view_incoming_dev);

    // Add multisig pieces to pending_tx
    ptx.multisig_sigs = multisig_sigs;
    ptx.multisig_tx_key_entropy = rct::rct2sk(rct::zero());  // not needed for Carrot txs
    ptx.multisig_enote_rr = multisig_enote_rr;

    return ptx;
}
//-------------------------------------------------------------------------------------------------------------------
void sign_multisig_partial_tx(
    const size_t threshold,
    const crypto::public_key &local_signer_pubkey,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &key_images,
    std::vector<std::vector<rct::key>*> &multisig_nonces_inout,
    pending_tx &ptx_inout,
    // Save partials for each tx attempt this signer participated in
    std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs_out)
{
    saved_partial_sigs_out.clear();

    // Checks
    CHECK_AND_ASSERT_THROW_MES(std::holds_alternative<carrot::CarrotTransactionProposalV1>(ptx_inout.construction_data),
        "sign multisig partial tx: pending_tx construction data is not CarrotTransactionProposalV1");
    const carrot::CarrotTransactionProposalV1& tx_proposal = std::get<carrot::CarrotTransactionProposalV1>(
        ptx_inout.construction_data);

    const size_t num_inputs = tx_proposal.input_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(num_inputs == ptx_inout.multisig_enote_rr.size(),
        "sign multisig partial tx: num input proposals != num rerandomization sets");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == key_images.size(),
        "sign multisig partial tx: num input proposals != num key images");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == multisig_nonces_inout.size(),
        "sign multisig partial tx: num input proposals != num multisig nonce sets");

    CHECK_AND_ASSERT_THROW_MES(multisig_selfsends_are_owned(tx_proposal, addr_dev),
        "sign multisig partial tx: failed checking selfsend is owned by this multisig account");

    std::vector<crypto::key_image> key_images_sorted = key_images;
    std::sort(key_images_sorted.begin(), key_images_sorted.end(), std::greater{});

    // Recreate pending_tx from tx_proposal (this should internally validate the tx proposal)
    pending_tx ptx_reproduced = make_pending_carrot_tx(tx_proposal,
        key_images_sorted,
        k_view_incoming_dev);
    ptx_reproduced.multisig_sigs = ptx_inout.multisig_sigs;
    ptx_reproduced.multisig_tx_key_entropy = ptx_inout.multisig_tx_key_entropy;
    ptx_reproduced.multisig_enote_rr = ptx_inout.multisig_enote_rr;
    CHECK_AND_ASSERT_THROW_MES(ptx_reproduced == ptx_inout, "sign multisig partial tx: failed recreating pending_tx");

    // Recover rerandomized outputs (for inputs)
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs{};
    for (size_t i = 0; i < num_inputs; ++i)
    {
        const carrot::InputProposalV1 &input_proposal = tx_proposal.input_proposals.at(i);
        const auto &rr_vec = ptx_inout.multisig_enote_rr.at(i);
        CHECK_AND_ASSERT_THROW_MES(rr_vec.size() == 4,
            "sign multisig partial tx: invalid rerandomization set (wrong size)");

        auto &rerandomized_output = rerandomized_outputs.emplace_back();
        rerandomized_output.input = fcmp_pp::calculate_fcmp_input_for_rerandomizations(
            onetime_address_ref(input_proposal),
            amount_commitment_ref(input_proposal),
            use_biased_hash_to_point(input_proposal),
            rr_vec[0],
            rr_vec[1],
            rr_vec[2],
            rr_vec[3]
        );

        memcpy(rerandomized_output.r_o, to_bytes(rr_vec[0]), 32);
        memcpy(rerandomized_output.r_i, to_bytes(rr_vec[1]), 32);
        memcpy(rerandomized_output.r_r_i, to_bytes(rr_vec[2]), 32);
        memcpy(rerandomized_output.r_c, to_bytes(rr_vec[3]), 32);
    }

    // Message to sign
    crypto::hash signable_message;
    carrot::make_signable_tx_hash_from_proposal_v1(tx_proposal,
        s_view_balance_dev,
        &k_view_incoming_dev,
        key_images_sorted,
        signable_message);

    // Update each tx attempt
    saved_partial_sigs_out.reserve(ptx_inout.multisig_sigs.size());

    for (multisig_sig &sig : ptx_inout.multisig_sigs)
    {
        // Add an entry to the partial sigs
        // This can be empty if the local signer is ignored by this attempt. It just needs to align with
        // `ptx_inout.multisig_sigs`.
        auto &partial_sigs = saved_partial_sigs_out.emplace_back();

        // Ignore?
        if (sig.ignore.find(local_signer_pubkey) != sig.ignore.cend())
            continue;

        // Checks
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.total_alpha_G.size(),
        "sign multisig partial tx: num input proposals != sig attempt total_alpha_G size");
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.total_alpha_H.size(),
        "sign multisig partial tx: num input proposals != sig attempt total_alpha_H size");
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.total_alpha_U.size(),
        "sign multisig partial tx: num input proposals != sig attempt total_alpha_U size");
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.total_kU.size(),
        "sign multisig partial tx: num input proposals != sig attempt total_kU size");
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.c_0.size(),
        "sign multisig partial tx: num input proposals != sig attempt c_0 size");
        CHECK_AND_ASSERT_THROW_MES(num_inputs == sig.s.size(),
        "sign multisig partial tx: num input proposals != sig attempt s size");

        // Local signing keys used
        crypto::secret_key aggregate_local_k = crypto::null_skey;

        for (const crypto::secret_key &k : local_multisig_keys)
        {
            crypto::public_key pkey;
            CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, pkey), "Failed to derive public key");

            // Skip sub-keys that supposedly already signed
            if (sig.signing_keys.find(pkey) != sig.signing_keys.end())
                continue;

            sc_add(to_bytes(aggregate_local_k), to_bytes(aggregate_local_k), to_bytes(k));
            sig.signing_keys.insert(pkey);
        }

        // Partially sign each input
        for (size_t i = 0; i < num_inputs; ++i)
        {
            const carrot::InputProposalV1 &input_proposal = tx_proposal.input_proposals.at(i);

            // Prep
            std::vector<crypto::secret_key> local_alpha(multisig::signing::kAlphaComponents);

            // Note: this clears alphas pulled from `multisig_nonces_inout`
            for (size_t n = 0; n < multisig::signing::kAlphaComponents; ++n)
            {
                if (!get_multisig_nonce(sig.used_L, multisig_nonces_inout.at(i), local_alpha.at(n)))
                    THROW_WALLET_EXCEPTION(tools::error::multisig_export_needed);
            }

            // Proposal
            multisig::SalProofMultisigProposal proposal;
            multisig::make_sal_multisig_proposal(
                rct::hash2rct(signable_message),
                rct::pk2rct(onetime_address_ref(input_proposal)),
                sig.total_kU.at(i),
                key_images.at(i),
                fcmp_pp::rerandomized_enote_from_raw(rerandomized_outputs.at(i)),
                proposal
            );

            // Get k^t_o
            crypto::public_key _main_address_spend_pubkeys[2];
            crypto::secret_key _sender_extension_g;
            crypto::secret_key sender_extension_t;
            CHECK_AND_ASSERT_THROW_MES(carrot::try_scan_opening_hint_sender_extensions(input_proposal,
                    carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),
                    &k_view_incoming_dev,
                    s_view_balance_dev,
                    _sender_extension_g,
                    sender_extension_t),
                "sign multisig partial tx:: failed computing sender extensions");

            // Partial signature
            crypto::secret_key x = aggregate_local_k;
            crypto::secret_key y = sender_extension_t;

            multisig::SalProofMultisigPartial partial_sig;
            multisig::make_sal_multisig_partial_sig(
                (const unsigned char)threshold,
                proposal,
                x,
                y,
                sig.total_alpha_G.at(i),
                sig.total_alpha_H.at(i),
                sig.total_alpha_U.at(i),
                local_alpha,
                partial_sig
            );

            // Include existing partial signatures in the returned partial_sig for simplicity when finalizing.
            sc_add(to_bytes(partial_sig.partial_proof.s_z), sig.c_0[i].bytes, to_bytes(partial_sig.partial_proof.s_z));
            sc_add(to_bytes(partial_sig.partial_proof.s_alpha), sig.s[i].bytes, to_bytes(partial_sig.partial_proof.s_alpha));
            sig.c_0[i] = (const rct::key&)partial_sig.partial_proof.s_z;
            sig.s[i] = (const rct::key&)partial_sig.partial_proof.s_alpha;

            // Save in case the signature is complete
            partial_sigs.push_back(partial_sig);
        }
    }
}
//-------------------------------------------------------------------------------------------------------------------
bool try_finalize_multisig_tx(
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &key_images,
    // One set of partial sigs per input for each signing attempt
    const std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs,
    pending_tx &ptx_inout)
{
    // Checks
    size_t num_attempts = ptx_inout.multisig_sigs.size();
    CHECK_AND_ASSERT_THROW_MES(num_attempts == saved_partial_sigs.size(),
        "try finalize multisig tx: num attempts != saved partial sigs size");

    CHECK_AND_ASSERT_THROW_MES(std::holds_alternative<carrot::CarrotTransactionProposalV1>(ptx_inout.construction_data),
        "sign multisig partial tx: pending_tx construction data is not CarrotTransactionProposalV1");
    const carrot::CarrotTransactionProposalV1& tx_proposal = std::get<carrot::CarrotTransactionProposalV1>(
        ptx_inout.construction_data);

    const size_t n_inputs = tx_proposal.input_proposals.size();
    const size_t n_outputs = tx_proposal.normal_payment_proposals.size()
        + tx_proposal.selfsend_payment_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(n_inputs, "no inputs");

    LOG_PRINT_L2("make all proofs for transaction proposal: "
        << n_inputs << "-in " << n_outputs << "-out, with "
        << tx_proposal.normal_payment_proposals.size() << " normal payment proposals, "
        << tx_proposal.selfsend_payment_proposals.size() << " self-send payment proposals, and a fee of "
        << tx_proposal.fee << " pXMR");

    for (size_t s = 0; s < num_attempts; ++s)
    {
        // Skip incomplete sigs
        if (saved_partial_sigs[s].size() == 0)
            continue;

        try {
            ptx_inout.tx = finalize_multisig_tx(
                tx_proposal,
                ptx_inout.multisig_enote_rr,
                tree_cache,
                curve_trees,
                addr_dev,
                k_view_incoming_dev,
                s_view_balance_dev,
                key_images,
                saved_partial_sigs[s]
            );

            return true;
        } catch (...) {
            MERROR("try finalize multisig tx: skipping failed attempt");
        }
    }

    return false;
}
//-------------------------------------------------------------------------------------------------------------------
multisig::signing::tx_builder_ringct_t sign_multisig_partial_tx_legacy(
    const cryptonote::account_keys &account_keys,
    const crypto::public_key &local_signer,
    wallet::PreCarrotTransactionProposal &proposal,
    std::vector<std::vector<rct::key>*> &multisig_nonces_inout,
    pending_tx &ptx_inout)
{
    // reconstruct the partially-signed transaction attempt to verify we are signing something that at least looks
    // like a transaction
    // note: the caller should further verify that the tx details are acceptable (inputs/outputs/memos/tx type)
    multisig::signing::tx_builder_ringct_t multisig_tx_builder;
    THROW_WALLET_EXCEPTION_IF(
        not multisig_tx_builder.init(
            account_keys,
            proposal.extra,
            proposal.subaddr_account,
            proposal.subaddr_indices,
            proposal.sources,
            proposal.splitted_dsts,
            proposal.change_dts,
            proposal.rct_config,
            proposal.use_rct,
            true,  //true = we are reconstructing the tx (it was first constructed by the tx proposer)
            ptx_inout.tx_key,
            ptx_inout.additional_tx_keys,
            ptx_inout.multisig_tx_key_entropy,
            ptx_inout.tx
        ),
        error::wallet_internal_error,
        "error: multisig::signing::tx_builder_ringct_t::init"
    );

    // go through each signing attempt for this transaction (each signing attempt corresponds to some subgroup of signers
    //   of size 'threshold')
    for (auto &sig: ptx_inout.multisig_sigs)
    {
        // skip this partial tx if it's intended for a subgroup of signers that doesn't include the local signer
        // note: this check can only weed out signers who provided multisig_infos to the multisig tx proposer's
        //       (initial author's) last call to import_multisig() before making this tx proposal; all other signers
        //       will encounter a 'need to export multisig' wallet error in get_multisig_k() below
        // note2: the 'need to export multisig' wallet error can also appear if a bad/buggy tx proposer adds duplicate
        //       'used_L' to the set of tx attempts, or if two different tx proposals use the same 'used_L' values and the
        //       local signer calls this function on both of them
        if (sig.ignore.find(local_signer) == sig.ignore.end())
        {
            rct::keyM local_nonces_k(proposal.selected_transfers.size(), rct::keyV(multisig::signing::kAlphaComponents));
            rct::key skey = rct::zero();
            auto wiper = epee::misc_utils::create_scope_leave_handler([&]{
                for (auto& e: local_nonces_k)
                    memwipe(e.data(), e.size() * sizeof(rct::key));
                memwipe(&skey, sizeof(rct::key));
            });

            // get local signer's nonces for this transaction attempt's inputs
            // note: whoever created 'exported_txs' has full power to match proposed tx inputs (selected_transfers)
            //       with the public nonces of the multisig signers who call this function (via 'used_L' as identifiers),
            //       however the local signer will only use a given nonce exactly once (even if a used_L is repeated)
            for (std::size_t i = 0; i < local_nonces_k.size(); ++i) {
                for (std::size_t j = 0; j < multisig::signing::kAlphaComponents; ++j) {
                    // Note: this clears alphas pulled from `multisig_nonces_inout`
                    crypto::secret_key temp;
                    if (!get_multisig_nonce(sig.used_L, multisig_nonces_inout.at(i), temp))
                        THROW_WALLET_EXCEPTION(tools::error::multisig_export_needed);
                    memcpy(local_nonces_k[i][j].bytes, to_bytes(temp), sizeof(rct::key));
                }
            }

            // round-robin signing: sign with all local multisig key shares that other signers have not signed with yet
            for (const auto &multisig_skey: account_keys.m_multisig_keys)
            {
                crypto::public_key multisig_pkey;
                CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(multisig_skey, multisig_pkey),
                    "Failed to derive public key");

                if (sig.signing_keys.find(multisig_pkey) == sig.signing_keys.end())
                {
                    sc_add(skey.bytes, skey.bytes, rct::sk2rct(multisig_skey).bytes);
                    sig.signing_keys.insert(multisig_pkey);
                }
            }

            THROW_WALLET_EXCEPTION_IF(
                not multisig_tx_builder.next_partial_sign(
                    sig.total_alpha_G, sig.total_alpha_H, local_nonces_k, skey, sig.c_0, sig.s
                ),
                error::wallet_internal_error,
                "error: multisig::signing::tx_builder_ringct_t::next_partial_sign"
            );
        }
    }

    return multisig_tx_builder;
}
//-------------------------------------------------------------------------------------------------------------------
} //namespace wallet
} //namespace tools
