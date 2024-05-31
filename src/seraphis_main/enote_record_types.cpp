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

// Records of seraphis enotes owned by some wallet.

//paired header
#include "enote_record_types.h"

//local headers
#include "crypto/crypto.h"
#include "crypto/x25519.h"
#include "ringct/rctTypes.h"
#include "seraphis_core/jamtis_support_types.h"
#include "seraphis_core/legacy_enote_types.h"
#include "tx_component_types.h"

//third party headers
#include <boost/optional/optional.hpp>

//standard headers

//forward declarations

namespace sp
{
bool operator==(const LegacyBasicEnoteRecord &a, const LegacyBasicEnoteRecord &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.address_index          == b.address_index &&
           a.tx_output_index        == b.tx_output_index &&
           a.unlock_time            == b.unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyIntermediateEnoteRecord &a, const LegacyIntermediateEnoteRecord &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.enote_view_extension   == b.enote_view_extension &&
           a.amount                 == b.amount &&
           a.amount_blinding_factor == b.amount_blinding_factor &&
           a.address_index          == b.address_index &&
           a.tx_output_index        == b.tx_output_index &&
           a.unlock_time            == b.unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteRecord &a, const LegacyEnoteRecord &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.enote_view_extension   == b.enote_view_extension &&
           a.amount                 == b.amount &&
           a.amount_blinding_factor == b.amount_blinding_factor &&
           a.key_image              == b.key_image &&
           a.address_index          == b.address_index &&
           a.tx_output_index        == b.tx_output_index &&
           a.unlock_time            == b.unlock_time;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpBasicEnoteRecordV1 &a, const SpBasicEnoteRecordV1 &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.input_context          == b.input_context &&
           a.nominal_address_tag    == b.nominal_address_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpIntermediateEnoteRecordV1&a, const SpIntermediateEnoteRecordV1 &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.input_context          == b.input_context &&
           a.amount                 == b.amount &&
           a.amount_blinding_factor == b.amount_blinding_factor &&
           a.address_index          == b.address_index;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const SpEnoteRecordV1 &a, const SpEnoteRecordV1 &b)
{
    return a.enote                  == b.enote &&
           a.enote_ephemeral_pubkey == b.enote_ephemeral_pubkey &&
           a.input_context          == b.input_context &&
           a.enote_view_extension_g == b.enote_view_extension_g &&
           a.enote_view_extension_x == b.enote_view_extension_x &&
           a.enote_view_extension_u == b.enote_view_extension_u &&
           a.amount                 == b.amount &&
           a.amount_blinding_factor == b.amount_blinding_factor &&
           a.key_image              == b.key_image &&
           a.address_index          == b.address_index &&
           a.type                   == b.type;
}
} //namespace sp
