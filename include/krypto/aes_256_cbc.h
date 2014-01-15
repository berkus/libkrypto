//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <openssl/aes.h>
#include "arsenal/byte_array.h"

namespace crypto {

class aes_256_cbc
{
    AES_KEY key_;

public:
    enum class type {
        encrypt,
        decrypt
    };

    aes_256_cbc(type which, byte_array const& key);

    // Encrypted data is padded to AES_BLOCK_SIZE.
    byte_array encrypt(byte_array const& in);
    // Decrypted data padding is not stripped.
    byte_array decrypt(byte_array const& in);
};

} // crypto namespace
