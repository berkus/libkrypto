//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <boost/tr1/array.hpp>
#include <openssl/aes.h>
#include "arsenal/byte_array.h"

namespace crypto {

/**
 * AES-128 block cipher, used in stream counter mode.
 */
class aes_128_ctr
{
    AES_KEY key_;

public:
    /**
     * Construct AES-128 cipher and set the @a key.
     */
    aes_128_ctr(byte_array const& key);
    ~aes_128_ctr();

    /**
     * Encrypt in counter mode.
     * @param  in      Block of data.
     * @param  iv      Initialization vector.
     * @return         Encrypted data.
     */
    byte_array encrypt(byte_array const& in, boost::array<uint8_t,AES_BLOCK_SIZE> iv);
    /**
     * Decrypt in counter mode.
     * @param  in      Block of encrypted data.
     * @param  iv      Initialization vector.
     * @return         Decrypted data.
     */
    inline byte_array decrypt(byte_array const& in, boost::array<uint8_t,AES_BLOCK_SIZE> iv) {
        return encrypt(in, iv);
    }
};

} // crypto namespace
