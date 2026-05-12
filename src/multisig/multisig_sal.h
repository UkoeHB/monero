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

#include "crypto/crypto.h"
#include "fcmp_pp/fcmp_pp_types_interop.h"
#include "ringct/rctTypes.h"

#include <cstdint>
#include <vector>


namespace multisig
{

////
// Multisig signature proposal for sal proofs
//
// WARNING: must only use a proposal to make ONE signature, after that the entropy and RerandomizedEnote stored here
//          should be deleted immediately
///
struct SalProofMultisigProposal final
{
    // message
    rct::key message;
    // main proof key K = k G
    rct::key K;
    // proof key k U
    rct::key kU;
    // key image KI = k Hp(K)
    crypto::key_image KI;
    // blinded enote keys and blinding secrets for the proof
    fcmp_pp::RerandomizedEnote rr_enote;

    // entropy for generating shared nonces
    crypto::secret_key entropy;
};

////
// Multisig partially signed composition proof (from one multisig signer)
// - only proof component KI is subject to multisig signing (proof privkey z is split between signers)
// - r_ki is the partial response from this multisig signer
///
struct SalProofMultisigPartial final
{
    // message
    rct::key message;
    // main proof key K
    rct::key K;
    // key image KI
    crypto::key_image KI;
    // blinded enote keys for the proof
    fcmp_pp::RerandomizedEnoteKeys rr_enote_keys;

    // partial proof
    // fields `s_alpha` and `s_z` are partial responses from one multisig signer
    fcmp_pp::SalProof partial_proof;
};

/**
* brief: make_sal_multisig_proposal - propose to make a multisig sal proof
* param: message - message to insert in the proof's Fiat-Shamir transform hash
* param: K - main proof key
* param: kU - proof key k U
* param: KI - key image
* param: rr_enote - enote with blinding factors
* outparam: proposal_out - proposal
*/
void make_sal_multisig_proposal(
    const rct::key &message,
    const rct::key &K,
    const rct::key &kU,
    const crypto::key_image &KI,
    const fcmp_pp::RerandomizedEnote &rr_enote,
    SalProofMultisigProposal &proposal_out
);
/**
* brief: make_sal_multisig_partial_sig - make local multisig signer's partial signature for a sal proof
*   - caller must validate the multisig proposal
*       - is the key image well-made and canonical?
*       - are the main key and kU legitimate?
*       - is the message correct?
* param: num_signers - the number of signers that will contribute to the final proof
* param: proposal - proof proposal to use when constructing the partial signature
* param: x - primary secret key
* param: y - secondary secret key (does NOT include r_o)
* param: total_alpha_G - {alpha1 G, alpha2 G}  (sum of components from signers)
* param: total_alpha_H - {alpha1 Hp(xG), alpha2 Hp(xG)}  (sum of components from signers)
* param: total_alpha_U - {alpha1 U, alpha2 U}  (sum of components from signers)
* param: local_nonce_1_priv - alpha_{ki,1,e} for local signer
* param: local_nonce_2_priv - alpha_{ki,2,e} for local signer
* outparam: partial_sig_out - partially signed sal proof
*/
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
);
/**
* brief: finalize_sal_multisig_proof - create a sal proof from multisig partial signatures
* param: partial_sigs - partial signatures from enough multisig signers to complete a full proof
* outparam: proof_out - sal proof
*/
void finalize_sal_multisig_proof(
    const std::vector<SalProofMultisigPartial> &partial_sigs,
    fcmp_pp::SalProof &proof_out
);
/**
* brief: verify_sal_proof - validates a sal proof (equivalent to fcmp_pp::verify_sal)
* param: message - the message signed
* param: keys - masked enote keys for the signature
* param: KI - the key image associated with the masked enote
* param: proof - sal proof to verify
*/
bool verify_sal_proof(
    const rct::key &message,
    const fcmp_pp::RerandomizedEnoteKeys &keys,
    const crypto::key_image &KI,
    const fcmp_pp::SalProof &proof
);

} //namespace multisig
