// Copyright (c) 2024, The Monero Project
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

// Serialization implementations for seraphis transaction components and transactions.

#pragma once

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/discretized_fee.h"
#include "seraphis_core/jamtis_destination.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_enote_types.h"
#include "seraphis_core/legacy_output_index.h"
#include "seraphis_crypto/math_utils.h"
#include "seraphis_crypto/sp_legacy_proof_helpers.h"
#include "seraphis_impl/checkpoint_cache.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/enote_record_types.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_main/tx_component_types.h"
#include "serialization/containers.h"
#include "serialization/crypto.h"
#include "serialization/serialization.h"
#include "serialization/tuple.h"
#include "serialization/variant.h"
#include "serialization/optional.h"

//third party headers

//standard headers

//forward declarations

namespace sp
{
namespace serialization
{
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
template <bool W, template <bool> class Archive, typename ValueType, typename... Args>
bool do_serialize_vec_exact(Archive<W> &ar, std::vector<ValueType> &v, const size_t implied_size,
    Args&&... args)
{
    // sanity check: there cannot be more elements remaining than bytes
    if constexpr (!W)
    {
        if (implied_size > ar.remaining_bytes())
            return false;
    }

    if (v.size() != implied_size)
    {
        if constexpr (W)
            return false;
        else
            v.resize(implied_size);
    }

    ar.begin_array();

    // Serialize each element
    for (size_t i{0}; i < v.size(); ++i)
    {
        if (i)
            ar.delimit_array();
        if (!do_serialize(ar, v[i], args...))
            return false;
    }

    ar.end_array();
    return ar.good();
}
} // namespace serialization
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
#define VEC_FIELD_EXACT_F(f, s, ...)                                     \
    do {                                                                 \
        ar.tag(#f);                                                      \
        const bool dsve_res{::sp::serialization::do_serialize_vec_exact( \
                ar, v.f, s VA_ARGS_COMMAPREFIX(__VA_ARGS__))};           \
        if (!dsve_res || !ar.good()) return false;                       \
    } while (0);
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
#define VEC_FIELD_OPT_EXACT_F(f, s, ...) \
    if (s == SIZE_MAX)                   \
        FIELD_F(f)                       \
    else if (s < 1024)                   \
        VEC_FIELD_EXACT_F(f, s)          \
    else                                 \
        return false;
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_FN(DiscretizedFee)
    static_assert(sizeof(v.fee_encoding) == 1, "should use a varint if int size != 1");
    FIELDS(v.fee_encoding)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCoinbaseEnoteCore)
    FIELD_F(onetime_address)
    VARINT_FIELD_F(amount)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteCore)
    FIELD_F(onetime_address)
    FIELD_F(amount_commitment)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteImageCore)
    FIELD_F(masked_address)
    FIELD_F(masked_commitment)
    FIELD_F(key_image)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(BulletproofPlus2Proof, const size_t implied_lr_size = SIZE_MAX)
    FIELD_F(A)
    FIELD_F(A1)
    FIELD_F(B)
    FIELD_F(r1)
    FIELD_F(s1)
    FIELD_F(d1)
    VEC_FIELD_OPT_EXACT_F(L, implied_lr_size)
    VEC_FIELD_OPT_EXACT_F(R, implied_lr_size)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyClsagProof, const size_t implied_s_size = SIZE_MAX)
    VEC_FIELD_OPT_EXACT_F(s, implied_s_size)
    FIELD_F(c1)
    FIELD_F(D)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCompositionProof)
    FIELD_F(c)
    FIELD_F(r_t1)
    FIELD_F(r_t2)
    FIELD_F(r_ki)
    FIELD_F(K_t1)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(GrootleProof)
    FIELD_F(A)
    FIELD_F(B)
    FIELD_F(f) /// @TODO: sizeless f serialization
    FIELD_F(X) /// @TODO: sizeless X serialization
    FIELD_F(zA)
    FIELD_F(z)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteImageV2)
    FIELD_F(masked_commitment)
    FIELD_F(key_image)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteImageV1)
    FIELD_F(core)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpCoinbaseEnoteV1)
    FIELD_F(core)
    FIELD_F(addr_tag_enc)
    VARINT_FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteV1)
    FIELD_F(core)
    FIELD_F(encoded_amount)
    FIELD_F(addr_tag_enc)
    VARINT_FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpBalanceProofV1, const size_t implied_lr_size = SIZE_MAX)
    FIELD_F(bpp2_proof, implied_lr_size)
    FIELD_F(remainder_blinding_factor)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyReferenceSetV2, const size_t implied_ring_size = SIZE_MAX)
    // if writing and we don't match the passed implied ring size, then fail
    if (W && implied_ring_size != SIZE_MAX && v.indices.size() != implied_ring_size)
        return false;

    // check that the passed implied ring size is not bigger than the number of remaining bytes
    if constexpr (!W)
    {
        if (implied_ring_size != SIZE_MAX && ar.remaining_bytes() < implied_ring_size)
            return false;
    }

    // if we don't have an implied size, serialize the actual size
    size_t actual_ring_size{v.indices.size()};
    if (implied_ring_size == SIZE_MAX)
        VARINT_FIELD_N("ring_size", actual_ring_size)
    else
        actual_ring_size = implied_ring_size;

    // if the ring size is 0, we can stop here
    if (actual_ring_size == 0)
        return ar.good();

    // start compacted indices data array
    ar.tag("indices_compressed");
    ar.begin_array();

    // if storing, construct the number of indices per ledger indexing amount
    std::vector<std::pair<rct::xmr_amount, size_t>> index_quantities_by_amount;
    if constexpr (W)
    {
        index_quantities_by_amount.reserve(actual_ring_size);
        index_quantities_by_amount.push_back({v.indices.begin()->ledger_indexing_amount, 0});
        for (const legacy_output_index_t i : v.indices)
        {
            if (i.ledger_indexing_amount != index_quantities_by_amount.back().first)
                index_quantities_by_amount.push_back({i.ledger_indexing_amount, 0});
            ++index_quantities_by_amount.back().second;
        }
    }

    // serialize the number of unique ledger indexing amounts
    size_t num_unique_amounts{index_quantities_by_amount.size() - 1};
    ar.serialize_varint(num_unique_amounts);
    ++num_unique_amounts;

    // sanity check num_unique_amounts
    if (num_unique_amounts == 0 || num_unique_amounts > actual_ring_size)
        return false;

    // for each unique indexing amount...
    rct::xmr_amount current_amount{0};
    size_t remaining_indices{actual_ring_size};
    auto writer_index_it{v.indices.begin()};
    for (size_t nth_amount{0}; nth_amount < num_unique_amounts; ++nth_amount)
    {
        // serialize ledger amount offset (-1 in the data if not the first amount)
        rct::xmr_amount amount_offset;
        if constexpr (W)
        {
            amount_offset = index_quantities_by_amount[nth_amount].first - current_amount;
            if (nth_amount)
                --amount_offset;
        }
        ar.delimit_array();
        ar.serialize_varint(amount_offset);
        if (nth_amount)
            ++amount_offset;

        // accumulate the ledger amount, checking for overflow
        if (amount_offset > MONEY_SUPPLY - current_amount)
            return false;
        current_amount += amount_offset;

        // serialize number of indices for this amount (-1 in the data), unless this is the last
        // amount in the list, we can imply the number as the number of indices not already serialized
        size_t num_indices_for_this_amount;
        if (nth_amount == num_unique_amounts - 1)
        {
            num_indices_for_this_amount = remaining_indices;
        }
        else // not last amount
        {
            if constexpr (W)
                num_indices_for_this_amount = index_quantities_by_amount[nth_amount].second - 1;
            ar.delimit_array();
            ar.serialize_varint(num_indices_for_this_amount);
            ++num_indices_for_this_amount;
        }

        // sanity check number of indices
        if (num_indices_for_this_amount > remaining_indices)
            return false;

        // serialize the indices as a list of cumulative offsets (-1 in the data if not first index)
        size_t current_index{0};
        for (size_t nth_index{0}; nth_index < num_indices_for_this_amount; ++nth_index)
        {
            // serialize index offset
            size_t index_offset;
            if constexpr (W)
            {
                index_offset = writer_index_it->index;
                if (nth_index)
                {
                    index_offset -= current_index + 1;
                }
            }
            ar.delimit_array();
            ar.serialize_varint(index_offset);
            if (nth_index)
                ++index_offset;

            // update iterators and check for index overflow
            --remaining_indices;
            if constexpr (W)
                ++writer_index_it;
            if (index_offset > SIZE_MAX - current_index)
                return false;
            current_index += index_offset;

            // if loading, insert legacy output index into the set
            if constexpr (!W)
                v.indices.insert({current_amount, current_index});
        }
    }

    // check that we loaded the right number of unique legacy indices
    if (v.indices.size() != actual_ring_size)
        return false;

    // end compacted indices data array
    ar.end_array();
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyRingSignatureV4, const size_t implied_ring_size = SIZE_MAX)
    FIELD_F(clsag_proof, implied_ring_size)
    FIELD_F(reference_set, implied_ring_size)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpImageProofV1)
    /// @TODO: sizeless f, X serialization
    FIELD_F(composition_proof)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpMembershipProofV1, const size_t implied_num_bins = SIZE_MAX)
    FIELD_F(grootle_proof)
    VEC_FIELD_OPT_EXACT_F(bin_loci, implied_num_bins)
    VARINT_FIELD_F(bin_rotation_factor)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxSupplementV1, const size_t implied_num_outputs = SIZE_MAX)
    const size_t implied_num_ephem_pubkeys{(2 == implied_num_outputs) ? 1 : implied_num_outputs};
    VEC_FIELD_OPT_EXACT_F(output_enote_ephemeral_pubkeys, implied_num_ephem_pubkeys)
    FIELD_F(tx_extra)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxCoinbaseV1)
    VARINT_FIELD_F(tx_semantic_rules_version)
    VARINT_FIELD_F(block_height)
    FIELD_F(outputs)
    FIELD_F(tx_supplement, v.outputs.size())
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpTxSquashedV1)
    VARINT_FIELD_F(tx_semantic_rules_version)

    FIELD_F(legacy_input_images)
    FIELD_F(sp_input_images)
    FIELD_F(outputs)

    const size_t num_legacy_inputs   = v.legacy_input_images.size();
    const size_t num_sp_inputs       = v.sp_input_images.size();
    const size_t num_outputs         = v.outputs.size();
    const size_t num_range_proofs    = num_sp_inputs + num_outputs;
    const size_t implied_bpp_lr_size = bpp_lr_length(num_range_proofs);

    FIELD_F(balance_proof, implied_bpp_lr_size)

    size_t clsag_ring_size = v.legacy_ring_signatures.size() ?
        v.legacy_ring_signatures[0].reference_set.indices.size() : 0;
    VARINT_FIELD(clsag_ring_size)

    VEC_FIELD_EXACT_F(legacy_ring_signatures, num_legacy_inputs, clsag_ring_size)
    VEC_FIELD_EXACT_F(sp_image_proofs, num_sp_inputs)

    // we can skip storing # of bins by calcing (n^m)/num_bin_members if using static config
    size_t num_bins{SIZE_MAX};
    if (v.tx_semantic_rules_version != SpTxSquashedV1::SemanticRulesVersion::MOCK)
    {
        const SemanticConfigSpRefSetV1 sp_ref_set_config{
            static_semantic_config_sp_ref_sets_v1(v.tx_semantic_rules_version)
        };
        num_bins = math::uint_pow(sp_ref_set_config.decomp_n, sp_ref_set_config.decomp_m)
            / sp_ref_set_config.num_bin_members;
    }

    VEC_FIELD_EXACT_F(sp_membership_proofs, num_sp_inputs, num_bins)
    FIELD_F(tx_supplement, num_outputs)
    FIELD_F(tx_fee)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteV1)
    FIELD_F(onetime_address)
    VARINT_FIELD_F(amount)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteV2)
    FIELD_F(onetime_address)
    FIELD_F(amount_commitment)
    FIELD_F(encoded_amount_blinding_factor)
    FIELD_F(encoded_amount)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteV3)
    FIELD_F(onetime_address)
    FIELD_F(amount_commitment)
    FIELD_F(encoded_amount)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteV4)
    FIELD_F(onetime_address)
    VARINT_FIELD_F(amount)
    FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteV5)
    FIELD_F(onetime_address)
    FIELD_F(amount_commitment)
    FIELD_F(encoded_amount)
    FIELD_F(view_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpBasicEnoteRecordV1)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(input_context)
    FIELD_F(nominal_address_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpIntermediateEnoteRecordV1)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(input_context)
    FIELD_F(amount)
    FIELD_F(amount_blinding_factor)
    FIELD_F(address_index)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteRecordV1)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(input_context)
    FIELD_F(enote_view_extension_g)
    FIELD_F(enote_view_extension_x)
    FIELD_F(enote_view_extension_u)
    FIELD_F(amount)
    FIELD_F(amount_blinding_factor)
    FIELD_F(key_image)
    FIELD_F(address_index)
    VARINT_FIELD_F(type)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyBasicEnoteRecord)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(address_index)
    FIELD_F(tx_output_index)
    FIELD_F(unlock_time)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyIntermediateEnoteRecord)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(enote_view_extension)
    FIELD_F(amount)
    FIELD_F(amount_blinding_factor)
    FIELD_F(address_index)
    FIELD_F(tx_output_index)
    FIELD_F(unlock_time)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteRecord)
    FIELD_F(enote)
    FIELD_F(enote_ephemeral_pubkey)
    FIELD_F(enote_view_extension)
    VARINT_FIELD_F(amount)
    FIELD_F(amount_blinding_factor)
    FIELD_F(key_image)
    FIELD_F(address_index)
    FIELD_F(tx_output_index)
    FIELD_F(unlock_time)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(legacy_output_index_t)
    VARINT_FIELD_F(ledger_indexing_amount)
    VARINT_FIELD_F(index)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyEnoteOriginContext)
    VARINT_FIELD_F(block_index)
    VARINT_FIELD_F(block_timestamp)
    FIELD_F(transaction_id)
    VARINT_FIELD_F(enote_tx_index)
    FIELD_F(legacy_enote_ledger_index)
    VARINT_FIELD_F(origin_status)
    FIELD_F(memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteOriginContextV1)
    VARINT_FIELD_F(block_index)
    VARINT_FIELD_F(block_timestamp)
    FIELD_F(transaction_id)
    VARINT_FIELD_F(enote_tx_index)
    FIELD_F(enote_ledger_index)
    VARINT_FIELD_F(origin_status)
    FIELD_F(memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpEnoteSpentContextV1)
    VARINT_FIELD_F(block_index)
    VARINT_FIELD_F(block_timestamp)
    FIELD_F(transaction_id)
    VARINT_FIELD_F(spent_status)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyContextualBasicEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyContextualIntermediateEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(LegacyContextualEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
    FIELD_F(spent_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpContextualBasicEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpContextualIntermediateEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(SpContextualEnoteRecordV1)
    FIELD_F(record)
    FIELD_F(origin_context)
    FIELD_F(spent_context)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(CheckpointCacheConfig)
    FIELD_F(num_unprunable)
    FIELD_F(max_separation)
    FIELD_F(density_factor)
END_SERIALIZE()
namespace jamtis
{
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisDestinationV1)
    FIELD_F(addr_K1)
    FIELD_F(addr_K2)
    FIELD_F(addr_K3)
    FIELD_F(addr_tag)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisPaymentProposalV1)
    FIELD_F(destination)
    FIELD_F(amount)
    FIELD_F(enote_ephemeral_privkey)
    FIELD_F(partial_memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
BEGIN_SERIALIZE_OBJECT_FN(JamtisPaymentProposalSelfSendV1)
    FIELD_F(destination)
    FIELD_F(amount)
    VARINT_FIELD_F(type)
    FIELD_F(enote_ephemeral_privkey)
    FIELD_F(partial_memo)
END_SERIALIZE()
//--------------------------------------------------------------------------------------------------
} // namespace jamtis
} // namespace sp

BLOB_SERIALIZER(sp::jamtis::address_index_t);
BLOB_SERIALIZER(sp::jamtis::address_tag_t);
BLOB_SERIALIZER(sp::jamtis::encoded_amount_t);

VARIANT_TAG(binary_archive, sp::SpCoinbaseEnoteV1, 0x71);
VARIANT_TAG(binary_archive, sp::SpEnoteV1, 0x72);

VARIANT_TAG(binary_archive, sp::LegacyEnoteV1, 0x73);
VARIANT_TAG(binary_archive, sp::LegacyEnoteV2, 0x74);
VARIANT_TAG(binary_archive, sp::LegacyEnoteV3, 0x75);
VARIANT_TAG(binary_archive, sp::LegacyEnoteV4, 0x76);
VARIANT_TAG(binary_archive, sp::LegacyEnoteV5, 0x77);
