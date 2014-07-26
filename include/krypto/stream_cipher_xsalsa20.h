//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/byte_array.h"

namespace crypto {

/**
 * XSalsa20 stream cipher.
 */
class xsalsa20
{
    std::string key_;

public:
    /**
     * Construct XSalsa20 cipher and set the @a key.
     */
    xsalsa20(byte_array const& key);
    ~xsalsa20();

    /**
     * Encrypt in counter mode.
     * @param  in      Block of data.
     * @param  iv      Initialization vector.
     * @return         Encrypted data.
     */
    byte_array encrypt(byte_array const& in, std::string iv);

    /**
     * Decrypt in counter mode.
     * @param  in      Block of encrypted data.
     * @param  iv      Initialization vector.
     * @return         Decrypted data.
     */
    inline byte_array decrypt(byte_array const& in, std::string iv) {
        return encrypt(in, iv);
    }
};

} // crypto namespace
