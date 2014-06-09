//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <boost/asio/buffer.hpp>
#include <crypto_stream_aes128ctr.h>
#include "krypto/aes_128_ctr.h"
#include "krypto/krypto.h"

namespace crypto {

aes_128_ctr::aes_128_ctr(byte_array const& key)
{
    key_ = key.as_string();
    assert(key_.length() == crypto_stream_aes128ctr_KEYBYTES);
}

aes_128_ctr::~aes_128_ctr()
{
    auto wrap = boost::asio::buffer((void*)&key_, crypto_stream_aes128ctr_KEYBYTES);
    crypto::cleanse(wrap); // Do not leave keys lying around.
}

byte_array aes_128_ctr::encrypt(byte_array const& in, std::string iv)
{
    assert(iv.length() == crypto_stream_aes128ctr_NONCEBYTES);
    return crypto_stream_aes128ctr_xor(in.as_string(), iv, key_);
}

} // crypto namespace
