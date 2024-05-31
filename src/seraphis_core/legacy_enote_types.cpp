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

//paired header
#include "legacy_enote_types.h"

//local headers
#include "common/variant.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"
#include "ringct/rctTypes.h"

//third party headers

//standard headers


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "seraphis"

namespace sp
{
//-------------------------------------------------------------------------------------------------------------------
const rct::key& onetime_address_ref(const LegacyEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<const rct::key&>
    {
        using variant_static_visitor::operator();  //for blank overload
        const rct::key& operator()(const LegacyEnoteV1 &enote) const { return enote.onetime_address; }
        const rct::key& operator()(const LegacyEnoteV2 &enote) const { return enote.onetime_address; }
        const rct::key& operator()(const LegacyEnoteV3 &enote) const { return enote.onetime_address; }
        const rct::key& operator()(const LegacyEnoteV4 &enote) const { return enote.onetime_address; }
        const rct::key& operator()(const LegacyEnoteV5 &enote) const { return enote.onetime_address; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
rct::key amount_commitment_ref(const LegacyEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<rct::key>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::key operator()(const LegacyEnoteV1 &enote) const { return rct::zeroCommit(enote.amount); }
        rct::key operator()(const LegacyEnoteV2 &enote) const { return enote.amount_commitment; }
        rct::key operator()(const LegacyEnoteV3 &enote) const { return enote.amount_commitment; }
        rct::key operator()(const LegacyEnoteV4 &enote) const { return rct::zeroCommit(enote.amount); }
        rct::key operator()(const LegacyEnoteV5 &enote) const { return enote.amount_commitment; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
rct::xmr_amount cleartext_amount_ref(const LegacyEnoteVariant &variant)
{
    struct visitor final : public tools::variant_static_visitor<rct::xmr_amount>
    {
        using variant_static_visitor::operator();  //for blank overload
        rct::xmr_amount operator()(const LegacyEnoteV1 &enote) const { return enote.amount; }
        rct::xmr_amount operator()(const LegacyEnoteV2 &enote) const { return 0; }
        rct::xmr_amount operator()(const LegacyEnoteV3 &enote) const { return 0; }
        rct::xmr_amount operator()(const LegacyEnoteV4 &enote) const { return enote.amount; }
        rct::xmr_amount operator()(const LegacyEnoteV5 &enote) const { return 0; }
    };

    return variant.visit(visitor());
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV1 gen_legacy_enote_v1()
{
    LegacyEnoteV1 temp;
    temp.onetime_address = rct::pkGen();
    temp.amount          = crypto::rand_idx<rct::xmr_amount>(0);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV2 gen_legacy_enote_v2()
{
    LegacyEnoteV2 temp;
    temp.onetime_address                = rct::pkGen();
    temp.amount_commitment              = rct::pkGen();
    temp.encoded_amount_blinding_factor = rct::skGen();
    temp.encoded_amount                 = rct::skGen();
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV3 gen_legacy_enote_v3()
{
    LegacyEnoteV3 temp;
    temp.onetime_address   = rct::pkGen();
    temp.amount_commitment = rct::pkGen();
    crypto::rand(sizeof(temp.encoded_amount), temp.encoded_amount.bytes);
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV4 gen_legacy_enote_v4()
{
    LegacyEnoteV4 temp;
    temp.onetime_address = rct::pkGen();
    temp.amount          = crypto::rand_idx<rct::xmr_amount>(0);
    temp.view_tag.data   = static_cast<char>(crypto::rand_idx<unsigned char>(0));
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
LegacyEnoteV5 gen_legacy_enote_v5()
{
    LegacyEnoteV5 temp;
    temp.onetime_address   = rct::pkGen();
    temp.amount_commitment = rct::pkGen();
    crypto::rand(sizeof(temp.encoded_amount), temp.encoded_amount.bytes);
    temp.view_tag.data     = static_cast<char>(crypto::rand_idx<unsigned char>(0));
    return temp;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteV1 &a, const LegacyEnoteV1 &b)
{
    return a.amount          == b.amount &&
           a.onetime_address == b.onetime_address;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteV2 &a, const LegacyEnoteV2 &b)
{
    return a.onetime_address                == b.onetime_address &&
           a.amount_commitment              == b.amount_commitment &&
           a.encoded_amount                 == b.encoded_amount &&
           a.encoded_amount_blinding_factor == b.encoded_amount_blinding_factor;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteV3 &a, const LegacyEnoteV3 &b)
{
    return a.onetime_address   == b.onetime_address &&
           a.amount_commitment == b.amount_commitment &&
           a.encoded_amount    == b.encoded_amount;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteV4 &a, const LegacyEnoteV4 &b)
{
    return a.amount          == b.amount &&
           a.onetime_address == b.onetime_address &&
           a.view_tag        == b.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteV5 &a, const LegacyEnoteV5 &b)
{
    return a.onetime_address   == b.onetime_address &&
           a.amount_commitment == b.amount_commitment &&
           a.encoded_amount    == b.encoded_amount &&
           a.view_tag          == b.view_tag;
}
//-------------------------------------------------------------------------------------------------------------------
bool operator==(const LegacyEnoteVariant &variant1, const LegacyEnoteVariant &variant2)
{
    // check they have the same type
    if (!LegacyEnoteVariant::same_type(variant1, variant2))
        return false;

    // use a visitor to test equality
    struct visitor final : public tools::variant_static_visitor<bool>
    {
        visitor(const LegacyEnoteVariant &other_ref) : other{other_ref} {}
        const LegacyEnoteVariant &other;

        using variant_static_visitor::operator();  //for blank overload
        bool operator()(const LegacyEnoteV1 &enote) const { return enote == other.unwrap<LegacyEnoteV1>(); }
        bool operator()(const LegacyEnoteV2 &enote) const { return enote == other.unwrap<LegacyEnoteV2>(); }
        bool operator()(const LegacyEnoteV3 &enote) const { return enote == other.unwrap<LegacyEnoteV3>(); }
        bool operator()(const LegacyEnoteV4 &enote) const { return enote == other.unwrap<LegacyEnoteV4>(); }
        bool operator()(const LegacyEnoteV5 &enote) const { return enote == other.unwrap<LegacyEnoteV5>(); }
    };

    return variant1.visit(visitor{variant2});
}
} //namespace sp
