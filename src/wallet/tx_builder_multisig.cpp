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
#include "carrot_core/exceptions.h"
#include "carrot_core/output_set_finalization.h"
#include "carrot_core/scan.h"
#include "carrot_impl/address_utils.h"
#include "carrot_impl/format_utils.h"
#include "carrot_impl/multi_tx_proposal_utils.h"
#include "carrot_impl/tx_builder_inputs.h"
#include "carrot_impl/tx_builder_outputs.h"
#include "carrot_impl/tx_proposal.h"
#include "common/apply_permutation.h"
#include "common/perf_timer.h"
#include "common/threadpool.h"
#include "crypto/generators.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "fcmp_pp/fcmp_pp_types.h"
#include "fcmp_pp/proof_len.h"
#include "fcmp_pp/prove.h"
#include "fcmp_pp/tower_cycle.h"
#include "misc_log_ex.h"
#include "ringct/bulletproofs_plus.h"
#include "ringct/rctSigs.h"
#include "tx_builder.h"

//third party headers

//standard headers
#include <algorithm>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.tx_builder_multisig"

namespace tools
{
namespace wallet
{
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// NOTE: Only supports legacy multisig, where subaddress extensions are additive and
// keys are shared on `G` while `T` is a placeholder.
static void prepare_legacy_multisig_input_signing_attempt(
    const carrot::OutputOpeningHintVariant &opening_hint,
    const std::unordered_set<crypto::public_key> &ignore_set,
    // Should only include 'active' signers, and `ignore_set` excludes active signers referenced here.
    const std::vector<multisig_info> &multisig_infos,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const size_t threshold,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    std::unordered_set<crypto::public_key> &all_used_L_inout,
    std::vector<crypto::public_key> &used_L_out,
    std::vector<crypto::secret_key> &local_alpha_out,
    rct::keyV alpha_G_out,
    rct::keyV alpha_H_out,
    rct::keyV alpha_U_out,
    crypto::key_image &key_image_out,
    crypto::public_key &kU_out,
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
    CHECK_AND_ASSERT_THROW_MES(try_scan_opening_hint_sender_extensions(opening_hint,
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
        for (size_t n = 0; n < multisig::signing::kAlphaComponents; ++n)
        {
            crypto::secret_key a = rct::rct2sk(rct::skGen());
            local_alpha_out.push_back(a);

            multisig::generate_multisig_nonces(
                onetime_address,
                a,
                (crypto::public_key&)alpha_G.emplace_back(),
                (crypto::public_key&)alpha_H.emplace_back(),
                (crypto::public_key&)alpha_U.emplace_back()
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
            crypto::key_image pki;
            crypto::generate_key_image(onetime_address, k, pki);
            rct::key kU_temp = rct::scalarmultKey(U, rct::sk2rct(k));

            rct::addKeys(ki, ki, rct::ki2rct(pki));
            rct::addKeys(kU, kU, kU_temp);
            used_ki.insert(pki);
        }

        // Other signers' keys
        size_t n_signers_used = 1;
        for (const &multisig_info : multisig_infos)
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
                    used_L_out.push(lr.m_L);
                    rct::addKeys(alpha_G[n], alpha_G[n], lr.m_L);
                    rct::addKeys(alpha_H[n], alpha_H[n], lr.m_R);
                    rct::addKeys(alpha_U[n], alpha_U[n], lr.m_U);
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
        kU_out = rct::rct2pk(kU);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
// NOTE: Only supports legacy multisig, where subaddress extensions are additive and
// keys are shared on `G` while `T` is a placeholder.
void get_multisig_key_image_from_opening_hint(
    const carrot::OutputOpeningHintVariant &opening_hint,
    const std::vector<multisig_info> &multisig_infos,
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
    CHECK_AND_ASSERT_THROW_MES(try_scan_opening_hint_sender_extensions(opening_hint,
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
        crypto::key_image pki;
        crypto::generate_key_image(onetime_address, k, pki);

        rct::addKeys(ki, ki, rct::ki2rct(pki));
        used_ki.insert(pki);
    }

    // Other signers' keys
    for (const &multisig_info : multisig_infos)
    {
        // Add ki and kU shares
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
cryptonote::transaction finalize_all_fcmp_pp_proofs(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const epee::span<const crypto::public_key> main_address_spend_pubkeys,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const carrot::spend_device &spend_dev)
{
    const size_t n_inputs = tx_proposal.input_proposals.size();
    const size_t n_outputs = tx_proposal.normal_payment_proposals.size()
        + tx_proposal.selfsend_payment_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(n_inputs, "no inputs");

    LOG_PRINT_L2("make all proofs for transaction proposal: "
        << n_inputs << "-in " << n_outputs << "-out, with "
        << tx_proposal.normal_payment_proposals.size() << " normal payment proposals, "
        << tx_proposal.selfsend_payment_proposals.size() << " self-send payment proposals, and a fee of "
        << tx_proposal.fee << " pXMR");

    // finalize key images
    std::vector<crypto::key_image> sorted_input_key_images;
    std::vector<std::size_t> key_image_order;
    carrot::get_sorted_input_key_images_from_proposal_v1(tx_proposal,
        spend_dev,
        sorted_input_key_images,
        &key_image_order);

    // prepare for proofs
    std::vector<fcmp_pp::OutputPair> output_pairs{};
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals{};
    carrot::encrypted_payment_id_t encrypted_payment_id{};
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs{};
    std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> rerandomized_outputs_by_ota{};
    prepare_for_fcmp_pp_proofs(
        tx_proposal,
        main_address_spend_pubkeys,
        k_view_incoming_dev,
        s_view_balance_dev,
        sorted_input_key_images,
        output_pairs,
        output_enote_proposals,
        encrypted_payment_id,
        rerandomized_outputs,
        rerandomized_outputs_by_ota
    );

    // call spend device to do SA/L proofs for each input
    crypto::hash signable_tx_hash;
    carrot::spend_device::signed_input_set_t signed_inputs;
    const bool sign_success = spend_dev.try_sign_carrot_transaction_proposal_v1(tx_proposal,
        rerandomized_outputs_by_ota,
        signable_tx_hash,
        signed_inputs);
    CHECK_AND_ASSERT_THROW_MES(sign_success, "Device declined to sign inputs");

    // sort and collect input infos in key image order
    tools::apply_permutation(key_image_order, rerandomized_outputs);
    tools::apply_permutation(key_image_order, output_pairs);
    std::vector<fcmp_pp::FcmpPpSalProof> sorted_sal_proofs;
    sorted_sal_proofs.reserve(signed_inputs.size());
    for (const auto &signed_input : signed_inputs)
        sorted_sal_proofs.push_back(signed_input.second.second);

    return finalize_fcmps_and_range_proofs(sorted_input_key_images,
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
pending_tx tx_proposal_to_multisig_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<std::unordered_set<crypto::public_key>> &ignore_sets,
    const std::vector<const *std::vector<multisig_info>> &multisig_infos,
    const size_t threshold,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &expected_key_images_sorted)
{
    // Checks
    size_t num_signing_attempts = ignore_sets.size();
    size_t num_inputs = tx_proposal.input_proposals.size();
    CHECK_AND_ASSERT_THROW_MES(num_inputs > 0,
        "tx proposal to multisig pending tx: no inputs");
    CHECK_AND_ASSERT_THROW_MES(num_inputs == multisig_infos.size(),
        "tx proposal to multisig pending tx: invalid number of multisig infos");

    // Entropy for all signing attempts
    crypto::secret_key entropy = rct::rct2sk(rct::skGen());

    // Rerandomization factors for each input
    crypto::public_key _main_address_spend_pubkeys[2];
    std::vector<fcmp_pp::OutputPair> _output_pairs{};
    std::vector<carrot::RCTOutputEnoteProposal> _output_enote_proposals{};
    carrot::encrypted_payment_id_t _encrypted_payment_id{};
    std::vector<FcmpRerandomizedOutputCompressed> rerandomized_outputs{};
    std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> rerandomized_outputs_by_ota{};
    prepare_for_fcmp_pp_proofs(
        tx_proposal,
        carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),,
        k_view_incoming_dev,
        s_view_balance_dev,
        expected_key_images_sorted,
        _output_pairs,
        _output_enote_proposals,
        _encrypted_payment_id,
        rerandomized_outputs,
        rerandomized_outputs_by_ota
    );

    std::vector<std::vector<crypto::secret_key>> multisig_enote_rr{};
    for (const FcmpRerandomizedOutputCompressed &rr_enote : rerandomized_outputs)
    {
        multisig_enote_rr.emplace_back{
            (const crypto::secret_key&)rr_enote.r_o,
            (const crypto::secret_key&)rr_enote.r_i,
            (const crypto::secret_key&)rr_enote.r_r_i,
            (const crypto::secret_key&)rr_enote.r_c,
        };
    }

    // Local signing keys used
    std::unordered_set<crypto::public_key> signing_keys{};
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
        k_view_incoming_dev,
        expected_key_images_sorted,
        signable_message);

    // Signing attempts
    std::vector<multisig_sig> multisig_sigs{};
    std::unordered_set<crypto::public_key> all_used_L{};

    for (size_t s = 0; s < num_signing_attempts; ++s)
    {
        std::vector<crypto::key_image> attempt_key_images{};
        std::vector<crypto::public_key> used_L{};
        rct::keyM total_alpha_G{};
        rct::keyM total_alpha_H{};
        rct::keyM total_alpha_U{};
        rct::keyV all_s_alpha{};
        rct::keyV all_s_z{};

        for (size_t i = 0; i < num_inputs; ++i)
        {
            // Prep
            rct::keyV local_alpha{};
            rct::keyV alpha_G{};
            rct::keyV alpha_H{};
            rct::keyV alpha_U{};

            crypto::key_image key_image;
            crypto::public_key kU;
            crypto::secret_key onetime_address_extension_g;
            crypto::secret_key onetime_address_extension_t;
            prepare_legacy_multisig_input_signing_attempt(
                tx_proposal.input_proposals.at(i),
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
            attempt_key_images.insert(key_image);

            // Proposal
            multisig::SalProofMultisigProposal proposal;
            multisig::make_sal_multisig_proposal(
                rct::hash2rct(signable_message),
                onetime_address,
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

            all_s_alpha.push_back(partial_sig.partial_proof.s_alpha);
            all_s_z.push_back(partial_sig.partial_proof.s_z);
        }

        // Check collected key images
        std::sort(attempt_key_images.begin(), attempt_key_images.end(), std::greater{});
        if (attempt_key_images != expected_key_images_sorted)
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
    ptx.multisig_tx_key_entropy = entropy;
    ptx.multisig_enote_rr = multisig_enote_rr;

    return ptx;
}
//-------------------------------------------------------------------------------------------------------------------
void sign_multisig_partial_tx()
{


    rerandomized_output.input = calculate_fcmp_input_for_rerandomizations(onetime_address,
        amount_commitment, use_biased_hash_to_point, r_o.at(i), r_i, r_r_i, r_c);
}
//-------------------------------------------------------------------------------------------------------------------
void finalize_multisig_tx()
{
    // Rerandomization factors for each input
    crypto::public_key _main_address_spend_pubkeys[2];
    std::vector<fcmp_pp::OutputPair> output_pairs{};
    std::vector<carrot::RCTOutputEnoteProposal> output_enote_proposals{};
    carrot::encrypted_payment_id_t encrypted_payment_id{};
    std::vector<FcmpRerandomizedOutputCompressed> _rerandomized_outputs{};
    std::unordered_map<crypto::public_key, FcmpRerandomizedOutputCompressed> _rerandomized_outputs_by_ota{};
    prepare_for_fcmp_pp_proofs(
        tx_proposal,
        carrot::get_all_main_address_spend_pubkeys_span(addr_dev, _main_address_spend_pubkeys),,
        k_view_incoming_dev,
        s_view_balance_dev,
        expected_key_images_sorted,
        output_pairs,
        output_enote_proposals,
        encrypted_payment_id,
        _rerandomized_outputs,
        _rerandomized_outputs_by_ota
    );
    return finalize_fcmps_and_range_proofs(sorted_input_key_images,
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
} //namespace wallet
} //namespace tools
