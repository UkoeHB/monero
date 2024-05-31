// Copyright (c) 2022, The Monero Project
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


#include "gtest/gtest.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/binned_reference_set.h"
#include "seraphis_core/binned_reference_set_utils.h"
#include "seraphis_impl/enote_store.h"
#include "seraphis_main/contextual_enote_record_types.h"
#include "seraphis_main/txtype_base.h"
#include "seraphis_main/txtype_coinbase_v1.h"
#include "seraphis_main/txtype_squashed_v1.h"
#include "seraphis_mocks/legacy_mock_keys.h"
#include "seraphis_mocks/seraphis_mocks.h"
#include "serialization/binary_utils.h"
#include "serialization/serialization.h"

using namespace sp::jamtis;
using namespace sp::mocks;

//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
static void make_transfers(MockLedgerContext &ledger_context,
    sp::SpEnoteStore &enote_store_in_out,
    const legacy_mock_keys &legacy_user_keys_A,
    const sp::jamtis::mocks::jamtis_mock_keys &user_keys_A)
{
    /// config
    const std::size_t max_inputs{1000};
    const std::size_t fee_per_tx_weight{1};
    const std::size_t legacy_ring_size{2};
    const std::size_t ref_set_decomp_n{2};
    const std::size_t ref_set_decomp_m{2};
    const std::size_t bin_radius{1};
    const std::size_t num_bin_members{2};
    const sp::scanning::ScanMachineConfig refresh_config{
        .reorg_avoidance_increment = 1, .max_chunk_size_hint = 1, .max_partialscan_attempts = 0};
    const FeeCalculatorMockTrivial fee_calculator;  // trivial calculator for easy fee (fee = fee/weight * 1 weight)
    const sp::SpBinnedReferenceSetConfigV1 bin_config{bin_radius, num_bin_members};
    const sp::SemanticConfigSpRefSetV1 sp_ref_set_config{.decomp_n = ref_set_decomp_n,
        .decomp_m                                                  = ref_set_decomp_m,
        .bin_radius                                                = bin_radius,
        .num_bin_members                                           = num_bin_members};

    /// send legacy coinbase enotes to random user to fill ledger
    std::vector<rct::xmr_amount> fake_legacy_enote_amounts(static_cast<std::size_t>(legacy_ring_size), 0);
    const rct::key fake_legacy_spendkey{rct::pkGen()};
    const rct::key fake_legacy_viewkey{rct::pkGen()};

    send_legacy_coinbase_amounts_to_user(fake_legacy_enote_amounts,
        fake_legacy_spendkey,
        fake_legacy_viewkey,
        ledger_context);

    /// send sp coinbase enotes to random user to fill ledger
    std::vector<rct::xmr_amount> fake_sp_enote_amounts(
        static_cast<std::size_t>(sp::compute_bin_width(bin_config.bin_radius)), 10);
    JamtisDestinationV1 fake_destination;
    fake_destination = gen_jamtis_destination_v1();

    send_sp_coinbase_amounts_to_user(fake_sp_enote_amounts, fake_destination, ledger_context);

    /// make one random user (user_keys_B)
    /// user keys
    sp::jamtis::mocks::jamtis_mock_keys user_keys_B;
    make_jamtis_mock_keys(user_keys_B);

    /// destination addresses
    JamtisDestinationV1 destination_A;
    JamtisDestinationV1 destination_B;
    make_random_address_for_user(user_keys_A, destination_A);
    make_random_address_for_user(user_keys_B, destination_B);

    /// user input selectors
    const InputSelectorMockV1 input_selector_A{enote_store_in_out};

    /// initial funding for user A:
    /// legacy 1000,1000,1000 seraphis 1000,1000,1000
    /// legacy:
    rct::key legacy_subaddr_spendkey_A;
    rct::key legacy_subaddr_viewkey_A;
    cryptonote::subaddress_index legacy_subaddr_index_A;
    std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map_A;
    gen_legacy_subaddress(legacy_user_keys_A.Ks,
        legacy_user_keys_A.k_v,
        legacy_subaddr_spendkey_A,
        legacy_subaddr_viewkey_A,
        legacy_subaddr_index_A);
    legacy_subaddress_map_A[legacy_subaddr_spendkey_A] = legacy_subaddr_index_A;
    send_legacy_coinbase_amounts_to_user(
            {10, 10, 10},
            legacy_subaddr_spendkey_A,
            legacy_subaddr_viewkey_A,
            ledger_context
        );
    refresh_user_enote_store_legacy_full(legacy_user_keys_A.Ks,
        legacy_subaddress_map_A,
        legacy_user_keys_A.k_s,
        legacy_user_keys_A.k_v,
        refresh_config,
        ledger_context,
        enote_store_in_out);

    /// seraphis:
    send_sp_coinbase_amounts_to_user({1000,1000,1000}, destination_A, ledger_context);
    refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);

    /// variables of one tx:
    /// user_B will receive 10 xmr per tx
    sp::SpTxSquashedV1 single_tx;
    std::pair<JamtisDestinationV1, rct::xmr_amount> outlays{destination_B, 10};
    const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};
    std::vector<JamtisPaymentProposalV1> normal_payments;
    std::vector<JamtisPaymentProposalSelfSendV1> selfsend_payments;

    /// send 5 confirmed txs
    for (int i = 0; i < 5; i++)
    {
        // make one tx
        normal_payments.clear();
        selfsend_payments.clear();
        construct_tx_for_mock_ledger_v1(legacy_user_keys_A,
            user_keys_A,
            input_selector_A,
            fee_calculator,
            fee_per_tx_weight,
            max_inputs,
            {{outlays.second, outlays.first, sp::TxExtra{}}},
            legacy_ring_size,
            ref_set_decomp_n,
            ref_set_decomp_m,
            bin_config,
            ledger_context,
            single_tx,
            selfsend_payments,
            normal_payments);

        // validate and submit to the mock ledger
        const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};
        CHECK_AND_ASSERT_THROW_MES(validate_tx(single_tx, tx_validation_context),
            "transfer funds single mock unconfirmed sp only: validating tx failed.");
        CHECK_AND_ASSERT_THROW_MES(try_add_tx_to_ledger(single_tx, ledger_context),
            "transfer funds single mock unconfirmed sp only: validating tx failed.");

        // refresh user stores
        refresh_user_enote_store(user_keys_A, refresh_config, ledger_context, enote_store_in_out);
    }
}
//-------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_empty)
{
    // make empty tx
    sp::SpTxCoinbaseV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    sp::SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_empty)
{
    // make empty tx
    sp::SpTxSquashedV1 tx{};

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    sp::SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check that the original tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_coinbase_standard)
{
    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, {}};

    // make a tx
    sp::SpTxCoinbaseV1 tx;
    make_mock_tx<sp::SpTxCoinbaseV1>(SpTxParamPackV1{.output_amounts = {1}}, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    sp::SpTxCoinbaseV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_coinbase_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_coinbase_v1_size_bytes(tx) == sp_tx_coinbase_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, seraphis_squashed_standard)
{
    // config
    SpTxParamPackV1 tx_params;

    tx_params.legacy_ring_size     = 2;
    tx_params.ref_set_decomp_n     = 2;
    tx_params.ref_set_decomp_m     = 2;
    tx_params.bin_config           = sp::SpBinnedReferenceSetConfigV1{.bin_radius = 1, .num_bin_members = 1};
    tx_params.legacy_input_amounts = {1};
    tx_params.sp_input_amounts     = {2, 3};
    tx_params.output_amounts       = {3};
    tx_params.discretized_fee      = sp::discretize_fee(3);

    const sp::SemanticConfigSpRefSetV1 sp_ref_set_config{
        .decomp_n        = tx_params.ref_set_decomp_n,
        .decomp_m        = tx_params.ref_set_decomp_m,
        .bin_radius      = tx_params.bin_config.bin_radius,
        .num_bin_members = tx_params.bin_config.num_bin_members,
    };

    // ledger context
    MockLedgerContext ledger_context{0, 10000};
    const TxValidationContextMock tx_validation_context{ledger_context, sp_ref_set_config};

    // make a tx
    sp::SpTxSquashedV1 tx;
    make_mock_tx<sp::SpTxSquashedV1>(tx_params, ledger_context, tx);

    // serialize the tx
    std::string serialized_tx;
    EXPECT_TRUE(::serialization::dump_binary(tx, serialized_tx));

    // recover the tx
    sp::SpTxSquashedV1 recovered_tx;
    EXPECT_TRUE(::serialization::parse_binary(serialized_tx, recovered_tx));

    // check the tx was recovered
    rct::key original_tx_id;
    rct::key recovered_tx_id;

    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(tx, original_tx_id));
    EXPECT_NO_THROW(get_sp_tx_squashed_v1_txid(recovered_tx, recovered_tx_id));

    EXPECT_TRUE(original_tx_id == recovered_tx_id);
    EXPECT_NO_THROW(EXPECT_TRUE(sp_tx_squashed_v1_size_bytes(tx) == sp_tx_squashed_v1_size_bytes(recovered_tx)));
    EXPECT_TRUE(validate_tx(tx, tx_validation_context));
    EXPECT_TRUE(validate_tx(recovered_tx, tx_validation_context));
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_destination_v1)
{
    // generate
    JamtisDestinationV1 dest{gen_jamtis_destination_v1()};

    // serialize
    std::string serialized_dest;
    EXPECT_TRUE(::serialization::dump_binary(dest, serialized_dest));

    // deserialize
    JamtisDestinationV1 recovered_dest;
    EXPECT_TRUE(::serialization::parse_binary(serialized_dest, recovered_dest));

    // compare
    EXPECT_EQ(dest, recovered_dest);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_v1)
{
    // generate
    JamtisPaymentProposalV1 payprop{gen_jamtis_payment_proposal_v1(7, 3)};

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, jamtis_payment_proposal_self_send_v1)
{
    // generate
    JamtisPaymentProposalSelfSendV1 payprop{
        gen_jamtis_selfsend_payment_proposal_v1(7, JamtisSelfSendType::SELF_SPEND, 3)};

    // serialize
    std::string serialized_payprop;
    EXPECT_TRUE(::serialization::dump_binary(payprop, serialized_payprop));

    // deserialize
    JamtisPaymentProposalSelfSendV1 recovered_payprop;
    EXPECT_TRUE(::serialization::parse_binary(serialized_payprop, recovered_payprop));

    // compare
    EXPECT_EQ(payprop, recovered_payprop);
}
//-------------------------------------------------------------------------------------------------------------------
template <typename... Ts> void match_tools_variant(const tools::variant<Ts...>&) {}
VARIANT_TAG(binary_archive, sp::SpEnoteCore, 0x37);
VARIANT_TAG(binary_archive, sp::SpCoinbaseEnoteCore, 0x88);
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, tools_variant)
{
    sp::SpEnoteCoreVariant enote_core{
            sp::SpEnoteCore{
                    .onetime_address = rct::pkGen(),
                    .amount_commitment = rct::zeroCommit(420)
                }
        };

    match_tools_variant(enote_core); // throws compile error if enote_core stops being of tools::variant type

    // serialize
    std::string serialized;
    EXPECT_TRUE(::serialization::dump_binary(enote_core, serialized));

    // deserialize
    sp::SpEnoteCoreVariant enote_core_recovered;
    EXPECT_TRUE(::serialization::parse_binary(serialized, enote_core_recovered));

    // test equal
    EXPECT_EQ(enote_core, enote_core_recovered);
}
//-------------------------------------------------------------------------------------------------------------------
TEST(seraphis_serialization, enote_store)
{
    // 1. generate enote_store and tx_store
    sp::SpEnoteStore enote_store_A{0, 0, 0};
    MockLedgerContext ledger_context{0, 10000};

    // 2. create user keys
    legacy_mock_keys legacy_user_keys_A;
    make_legacy_mock_keys(legacy_user_keys_A);
    sp::jamtis::mocks::jamtis_mock_keys user_keys_A;
    make_jamtis_mock_keys(user_keys_A);

    // 3. make some txs
    for (int i = 0; i < 5; i++)
        make_transfers(ledger_context, enote_store_A, legacy_user_keys_A, user_keys_A);

    // 4. get all sp enote records
    std::vector<sp::SpContextualEnoteRecordV1> all_sp_enote_records;
    all_sp_enote_records.reserve(enote_store_A.sp_records().size());

    for (const auto &enote_record : enote_store_A.sp_records())
        all_sp_enote_records.push_back(enote_record.second);

    // 5. serialize sp_contextual_enote_record
    std::string serialized_enote_record;
    EXPECT_TRUE(::serialization::dump_binary(all_sp_enote_records[0], serialized_enote_record));

    // 6. deserialize sp_contextual_enote_record
    sp::SpContextualEnoteRecordV1 recovered_enote_record;
    EXPECT_TRUE(::serialization::parse_binary(serialized_enote_record, recovered_enote_record));

    // 7. compare sp_contextual_enote_record
    EXPECT_EQ(all_sp_enote_records[0], recovered_enote_record);

    // 8. get all legacy_contextual_enote_records
    std::vector<sp::LegacyContextualEnoteRecordV1> all_legacy_enote_records;
    all_sp_enote_records.reserve(enote_store_A.legacy_records().size());

    for (const auto &enote_record : enote_store_A.legacy_records())
        all_legacy_enote_records.push_back(enote_record.second);

    // 9. serialize legacy_contextual_enote_record
    std::string serialized_legacy_enote_record;
    EXPECT_TRUE(::serialization::dump_binary(all_legacy_enote_records[0], serialized_legacy_enote_record));

    // 10. deserialize legacy_contextual_enote_record
    sp::LegacyContextualEnoteRecordV1 recovered_legacy_enote_record;
    EXPECT_TRUE(::serialization::parse_binary(serialized_legacy_enote_record, recovered_legacy_enote_record));

    // 11. compare legacy_contextual_enote_record
    EXPECT_EQ(all_legacy_enote_records[0], recovered_legacy_enote_record);

    // 12. serialize enote_store
    std::string serialized_enote_store;
    EXPECT_TRUE(::serialization::dump_binary(enote_store_A, serialized_enote_store));

    // 13. deserialize enote_store
    sp::SpEnoteStore recovered_enote_store;
    EXPECT_TRUE(::serialization::parse_binary(serialized_enote_store, recovered_enote_store));

    // 14. compare enote_store
    EXPECT_TRUE(recovered_enote_store==enote_store_A);
}
