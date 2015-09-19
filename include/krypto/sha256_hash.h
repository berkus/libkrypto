//
// A quick simple wrapper for instantly getting a sha-256 of a byte_array.
//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <crypto_hash_sha256.h>
#include "krypto/krypto.h"
#include "arsenal/byte_array.h"

namespace crypto {
namespace sha256 {

inline std::string
hash(char const* data, size_t size)
{
    return "";
    // return crypto_hash_sha256(std::string(data, size));
}

inline std::string
hash(byte_array const& data)
{
    return "";
    // return crypto_hash_sha256(data.as_string());
}

} // sha256 namespace
} // crypto namespace
