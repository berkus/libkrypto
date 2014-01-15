//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <openssl/dh.h>
#include "arsenal/flurry.h"

class byte_array;

namespace crypto {
namespace utils {

// Little helper functions for BIGNUM to byte_array conversions.
BIGNUM* ba2bn(byte_array const& ba);
byte_array bn2ba(BIGNUM const* bn);

} // utils namespace
} // crypto namespace

// Flurry serialization helpers.
inline flurry::oarchive& operator << (flurry::oarchive& oa, BIGNUM* const& num)
{
    oa << crypto::utils::bn2ba(num);
    return oa;
}

inline flurry::iarchive& operator >> (flurry::iarchive& ia, BIGNUM*& num)
{
    byte_array ba;
    ia >> ba;
    num = crypto::utils::ba2bn(ba);
    return ia;
}
