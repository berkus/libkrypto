//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <boost/asio/buffer.hpp>
#include "aes_128_ctr.h"
#include "krypto.h"

namespace crypto {

aes_128_ctr::aes_128_ctr(byte_array const& key)
{
    int keysize = key.size() * 8;
    assert(keysize == 128);
    int rc = AES_set_encrypt_key((const unsigned char*)key.const_data(), keysize, &key_);
    assert(rc == 0);
    if (rc != 0) {
        throw std::runtime_error("Cannot set AES encryption key");
    }
}

aes_128_ctr::~aes_128_ctr()
{
    auto wrap = boost::asio::buffer((void*)&key_, 128/8);
    crypto::cleanse(wrap); // Do not leave keys lying around.
}

byte_array aes_128_ctr::encrypt(byte_array const& in, boost::array<uint8_t,AES_BLOCK_SIZE> iv)
{
    uint8_t ecount[AES_BLOCK_SIZE]{0}; // Encryption state
    unsigned int num{0};

    byte_array out;
    out.resize(in.size());

    AES_ctr128_encrypt((const uint8_t*)in.const_data(), (uint8_t*)out.data(), in.size(),
        &key_, iv.data(), ecount, &num);

    return out;
}

} // crypto namespace
