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

#pragma once

//local headers
#include "carrot_impl/address_device.h"
#include "carrot_impl/output_opening_types.h"
#include "carrot_impl/tx_proposal.h"
#include "multisig/multisig_sal.h"
#include "multisig/multisig_tx_builder_ringct.h"
#include "wallet2_basic/wallet2_types.h"
#include "tx_builder.h"

//third party headers

//standard headers
#include <set>
#include <vector>

//forward declarations

namespace tools
{
namespace wallet
{

void get_multisig_key_image_from_opening_hint(
    const carrot::OutputOpeningHintVariant &opening_hint,
    const std::vector<wallet2_basic::multisig_info> &multisig_infos,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    crypto::key_image &key_image_out);


pending_tx tx_proposal_to_multisig_pending_tx(
    const carrot::CarrotTransactionProposalV1 &tx_proposal,
    const std::vector<std::set<crypto::public_key>> &ignore_sets,
    const std::vector<const std::vector<wallet2_basic::multisig_info>*> &multisig_infos,
    const size_t threshold,
    const crypto::public_key &local_signer_pubkey,
    const std::vector<crypto::secret_key> &local_multisig_keys,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device &k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &expected_key_images,
    std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs_out);


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
    std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs_out);


bool try_finalize_multisig_tx(
    const fcmp_pp::curve_trees::TreeCacheV1 &tree_cache,
    const fcmp_pp::curve_trees::CurveTreesV1 &curve_trees,
    const carrot::address_device &addr_dev,
    const carrot::view_incoming_key_device *k_view_incoming_dev,
    const carrot::view_balance_secret_device *s_view_balance_dev,
    const std::vector<crypto::key_image> &key_images,
    // One set of partial sigs per input for each signing attempt
    const std::vector<std::vector<multisig::SalProofMultisigPartial>> &saved_partial_sigs,
    pending_tx &ptx_inout);

multisig::signing::tx_builder_ringct_t sign_multisig_partial_tx_legacy(
    const cryptonote::account_keys &account_keys,
    const crypto::public_key &local_signer,
    wallet::PreCarrotTransactionProposal &proposal,
    std::vector<std::vector<rct::key>*> &multisig_nonces_inout,
    pending_tx &ptx_inout);

} //namespace wallet
} //namespace tools
