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

#include "gtest/gtest.h"

#include "carrot_core/config.h"
#include "carrot_core/exceptions.h"
#include "carrot_impl/format_utils.h"
#include "carrot_impl/subaddress_map_legacy.h"
#include "carrot_mock_helpers.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/tx_verification_utils.h"
#include "fake_pruned_blockchain.h"
#include "fcmp_pp/prove.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "tx_construction_helpers.h"
#include "wallet/tx_builder.h"
#include "wallet/tx_builder_multisig.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "unit_tests.wallt_tx_builder_multisig"

//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static std::vector<std::string> exchange_round(std::vector<tools::wallet2>& wallets, const std::vector<std::string>& infos)
{
    std::vector<std::string> new_infos;
    new_infos.reserve(infos.size());

    for (size_t i = 0; i < wallets.size(); ++i)
        new_infos.push_back(wallets[i].exchange_multisig_keys("", infos));

    return new_infos;
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void make_wallets(const unsigned int M, const unsigned int N, std::vector<tools::wallet2> &wallets_out)
{
    ASSERT_TRUE(N > 1);
    ASSERT_TRUE(M <= N);
    std::vector<tools::wallet2> wallets(N);
    std::uint32_t total_rounds_required = multisig::multisig_setup_rounds_required(N, M);
    std::uint32_t rounds_complete{0};

    // initialize wallets, get first round multisig kex msgs
    std::vector<std::string> initial_infos(wallets.size());

    for (size_t i = 0; i < N; ++i)
    {
        crypto::secret_key k_s = rct::rct2sk(rct::skGen());
        wallets[i].init("", boost::none, "", 0, true, epee::net_utils::ssl_support_t::e_ssl_support_disabled);
        wallets[i].set_offline(true);
        wallets[i].generate("", "", k_s, true, false);

        wallets[i].decrypt_keys("");
        ASSERT_TRUE(k_s == wallets[i].get_account().get_keys().m_spend_secret_key);
        initial_infos[i] = wallets[i].get_multisig_first_kex_msg();
        wallets[i].encrypt_keys("");
    }

    // wallets should not be multisig yet
    for (const auto& wallet: wallets)
        ASSERT_FALSE(wallet.get_multisig_status().multisig_is_active);

    // make wallets multisig, get second round kex messages (if appropriate)
    std::vector<std::string> intermediate_infos(wallets.size());

    for (size_t i = 0; i < wallets.size(); ++i)
    {
        intermediate_infos[i] = wallets[i].make_multisig("", initial_infos, M);
    }

    ++rounds_complete;

    // perform kex rounds until kex is complete
    multisig::multisig_account_status ms_status{wallets[0].get_multisig_status()};
    while (!ms_status.is_ready)
    {
        intermediate_infos = exchange_round(wallets, intermediate_infos);

        ms_status = wallets[0].get_multisig_status();
        ++rounds_complete;
    }

    EXPECT_EQ(total_rounds_required, rounds_complete);

    wallets_out = std::move(wallets);
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
static void run_test(const size_t M, const size_t N)
{
    ASSERT_TRUE(N > 1);
    ASSERT_TRUE(M <= N);

    // 1. create fake blockchain
    // 2. create M-of-N multisig wallet2 instances
    // 3. create Bob wallet2 instance
    // 4. send a mix of fake-input legacy and carrot txs to the M-of-N
    // 5. step blockchain forward 10 blocks
    // 6. scan blockchain with the M-of-N wallet
    // 7. export info for the M-of-N
    // 8. import info for the M-of-N
    // 9. create carrot transaction proposal with one wallet in the M-of-N
    // 10. initialize pending transaction
    // 11. add signatures and finalize the tx with another M-of-N participant
    // 12. serialize tx
    // 13. deserialize tx
    // 14. check ver_non_input_consensus()
    // 15. check verRctNonSemanticsSimple()
    // 16. add the M-of-N's transaction to blockchain
    // 17. scan blockchain with Bob's wallet and assert money received
    // 18. scan blockchain with the M-of-N's wallets and assert money left

    // 1.
    LOG_PRINT_L2("Initiating my imaginary, friendly chain of blocks");
    mock::fake_pruned_blockchain bc(0);

    // 2.
    LOG_PRINT_L2("Generating wallets for a M-of-N multisig setup");
    std::vector<tools::wallet2> multisig_wallets;
    make_wallets(M, N, multisig_wallets);
    for (auto &w : multisig_wallets)
        bc.init_wallet_for_starting_block(w);
    const cryptonote::account_public_address multisig_main_addr =
        multisig_wallets[0].get_account().get_keys().m_account_address;

    // 3.
    LOG_PRINT_L2("Generating wallet for Bob");
    tools::wallet2 bob(cryptonote::MAINNET, /*kdf_rounds=*/1, /*unattended=*/true);
    bob.set_offline(true);
    bob.generate("", "");
    const cryptonote::account_public_address bob_main_addr = bob.get_account().get_keys().m_account_address;
    bc.init_wallet_for_starting_block(bob);

    // 4.
    LOG_PRINT_L2("Sending transactions from the aether to the M-of-N (0)");
    const rct::xmr_amount amount0 = rct::randXmrAmount(COIN);
    std::vector<cryptonote::tx_destination_entry> dests0{cryptonote::tx_destination_entry(amount0, multisig_main_addr, false)};
    cryptonote::transaction tx = mock::construct_pre_carrot_tx_with_fake_inputs(dests0, /*fee=*/1234, /*hf_version=*/2);
    bc.add_block(2, {std::move(tx)}, mock::null_addr);
    LOG_PRINT_L2("Sending transactions from the aether to the M-of-N (1)");
    const rct::xmr_amount amount1 = rct::randXmrAmount(COIN);
    std::vector<cryptonote::tx_destination_entry> dests1{
        cryptonote::tx_destination_entry(amount1, multisig_wallets[0].get_subaddress({0, 13}), true)
    };
    cryptonote::account_base aether;
    aether.generate();
    tx = mock::construct_carrot_pruned_transaction_fake_inputs(
        {carrot::mock::convert_normal_payment_proposal_v1(dests1.front())}, {}, aether.get_keys()
    );
    bc.add_block(HF_VERSION_CARROT, {std::move(tx)}, mock::null_addr);

    // 5.
    //!@TODO: figure out why membership proving fails if there's fewer leaves than the curve1 width
    const size_t target_num_outputs = fcmp_pp::curve_trees::SELENE_CHUNK_WIDTH * fcmp_pp::curve_trees::HELIOS_CHUNK_WIDTH + 7;
    while (bc.num_outputs() < target_num_outputs)
        bc.add_block(HF_VERSION_CARROT, {}, mock::null_addr, target_num_outputs - bc.num_outputs());

    LOG_PRINT_L2("Twiddling thumbs");
    for (size_t i = 0; i < CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; ++i)
        bc.add_block(HF_VERSION_CARROT, {}, mock::null_addr);

    // 6.
    LOG_PRINT_L2("M-of-N scanning the blockchain");
    for (auto &w : multisig_wallets)
    {
        uint64_t blocks_added = bc.refresh_wallet(w);
        ASSERT_EQ(bc.height()-1, blocks_added);
        ASSERT_EQ(2, w.m_transfers.size());
        // really, we care about unlocked_balance_all() for sending, but that call uses RPC
        ASSERT_EQ(amount0 + amount1, w.balance_all(true));
    }

    // 7.
    LOG_PRINT_L2("M-of-N exporting info");
    std::vector<cryptonote::blobdata> multisig_exports;
    for (auto &w : multisig_wallets)
    {
        w.decrypt_keys("");
        multisig_exports.emplace_back(w.export_multisig());
        w.encrypt_keys("");
    }

    // 8.
    LOG_PRINT_L2("M-of-N importing info");
    for (auto &w : multisig_wallets)
    {
        w.decrypt_keys("");
        w.import_multisig(multisig_exports, false);
        w.encrypt_keys("");
    }

    // 9.
    LOG_PRINT_L2("A M-of-N participant proposes a tx to pay Bob");
    // divide by 2 to make sure M-of-N has enough for the fee
    const rct::xmr_amount out_amount = rct::randXmrAmount(amount0 + amount1) / 2;
    const std::vector<carrot::CarrotTransactionProposalV1> tx_proposals = 
        tools::wallet::make_carrot_transaction_proposals_wallet2_transfer(
            multisig_wallets[0].m_transfers,
            carrot::subaddress_map_legacy(multisig_wallets[0].m_subaddresses),
            {cryptonote::tx_destination_entry(out_amount, bob_main_addr, false)},
            /*fee_per_weight=*/1,
            /*extra=*/{},
            /*subaddr_account=*/0,
            /*subaddr_indices=*/{},
            /*ignore_above=*/std::numeric_limits<rct::xmr_amount>::max(),
            /*ignore_below=*/0,
            /*max_n_inputs=*/0,
            {},
            /*top_block_index=*/bc.height()-1);

    ASSERT_EQ(1, tx_proposals.size());

    // 10.
    LOG_PRINT_L2("The M-of-N participant makes a tx");
    multisig_wallets[0].decrypt_keys("");
    tools::wallet::pending_tx pending_tx = tools::detail::transfer_details_and_tx_proposal_to_multisig_pending_tx(
      tx_proposals[0],
      multisig_wallets[0]);
    tools::wallet2::multisig_tx_set multisig_tx_set = multisig_wallets[0].make_multisig_tx_set({pending_tx});
    std::string tx_set_str = multisig_wallets[0].save_multisig_tx(multisig_tx_set);
    multisig_wallets[0].encrypt_keys("");

    // 11.
    for (size_t i = 1; i < M; ++i)
    {
        LOG_PRINT_L2("Another M-of-N participant signs and finalizes the partial tx");
        multisig_wallets[i].decrypt_keys("");
        tools::wallet2::multisig_tx_set tx_set_recovered;
        multisig_wallets[i].parse_multisig_tx_from_str(tx_set_str, tx_set_recovered);
        std::vector<crypto::hash> txids_computed;
        multisig_wallets[i].sign_multisig_tx(tx_set_recovered, txids_computed);
        multisig_wallets[i].encrypt_keys("");
        ASSERT_EQ(txids_computed.size(), 1);
        // Save for next round
        multisig_tx_set = std::move(tx_set_recovered);
    }

    // 12.
    LOG_PRINT_L2("Serializing pending tx");
    auto final_tx = multisig_tx_set.m_ptx[0].tx;
    const cryptonote::blobdata to_bob_tx_blob = cryptonote::tx_to_blob(final_tx);

    // 13.
    LOG_PRINT_L2("Deserializing pending tx");
    cryptonote::transaction to_bob_tx;
    ASSERT_TRUE(cryptonote::parse_and_validate_tx_from_blob(to_bob_tx_blob, to_bob_tx));

    // 14.
    LOG_PRINT_L2("Checking ver_non_input_consensus");
    ASSERT_GE(bc.hf_version(), HF_VERSION_FCMP_PLUS_PLUS);
    cryptonote::tx_verification_context tvc{};
    ASSERT_TRUE(cryptonote::ver_non_input_consensus(to_bob_tx, tvc, bc.hf_version()));
    EXPECT_FALSE(tvc.m_verifivation_failed);

    // 15.
    LOG_PRINT_L2("Checking verRctNonSemanticsSimple");
    const auto tree_root = bc.get_fcmp_tree_root_at(bc.height() - 1);
    ASSERT_TRUE(cryptonote::Blockchain::expand_transaction_2(to_bob_tx,
        cryptonote::get_transaction_prefix_hash(to_bob_tx),
        /*pubkeys=*/{},
        tree_root));
    EXPECT_TRUE(rct::verRctNonSemanticsSimple(to_bob_tx.rct_signatures));

    // 16.
    LOG_PRINT_L2("Adding to blockchain");
    const rct::xmr_amount to_bob_tx_fee = to_bob_tx.rct_signatures.txnFee;
    bc.add_block(HF_VERSION_CARROT, {std::move(to_bob_tx)}, mock::null_addr);

    // 17.
    LOG_PRINT_L2("Bob scans received money");
    ASSERT_EQ(0, bob.balance_all(true));
    auto blocks_added = bc.refresh_wallet(bob);
    ASSERT_EQ(bc.height()-1, blocks_added);
    ASSERT_EQ(1, bob.m_transfers.size());
    EXPECT_EQ(out_amount, bob.balance_all(true));

    // 18.
    // note: don't need to export/import again since we already got key images for originally-owned enotes
    LOG_PRINT_L2("M-of-N scans sent money");
    for (auto &w : multisig_wallets)
    {
        const rct::xmr_amount old_balance = w.balance_all(true);
        ASSERT_GE(old_balance, out_amount + to_bob_tx_fee);
        blocks_added = bc.refresh_wallet(w);
        ASSERT_EQ(1, blocks_added);
        const rct::xmr_amount new_balance = w.balance_all(true);
        ASSERT_LT(new_balance, old_balance);
        EXPECT_EQ(new_balance + out_amount + to_bob_tx_fee, old_balance);
    }
}
//----------------------------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------------------------
TEST(wallet_tx_builder_multisig, wallet2_scan_propose_sign_prove_member_and_scan_1_of_2)
{
    run_test(1, 2);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(wallet_tx_builder_multisig, wallet2_scan_propose_sign_prove_member_and_scan_2_of_2)
{
    run_test(2, 2);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(wallet_tx_builder_multisig, wallet2_scan_propose_sign_prove_member_and_scan_2_of_3)
{
    run_test(2, 3);
}
//----------------------------------------------------------------------------------------------------------------------
TEST(wallet_tx_builder_multisig, wallet2_scan_propose_sign_prove_member_and_scan_3_of_3)
{
    run_test(3, 3);
}
//----------------------------------------------------------------------------------------------------------------------
