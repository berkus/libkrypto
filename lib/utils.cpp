//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "utils.h"
#include "byte_array.h"

namespace ssu {
namespace crypto {
namespace utils {

// Little helper functions for BIGNUM to byte_array conversions.

BIGNUM* ba2bn(byte_array const& ba)
{
    return BN_bin2bn((const unsigned char*)ba.data(), ba.size(), nullptr);
}

byte_array bn2ba(BIGNUM const* bn)
{
    assert(bn != nullptr);
    byte_array ba;
    ba.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, (unsigned char*)ba.data());
    return ba;
}

} // utils namespace
} // crypto namespace
} // ssu namespace
