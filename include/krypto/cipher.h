//
// Copyright (c) 2013, Aldrin D'Souza
// All rights reserved.
// http://opensource.org/licenses/BSD-2-Clause
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY {{THE COPYRIGHT HOLDERS AND CONTRIBUTORS}}
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL {{THE COPYRIGHT HOLDER OR
// CONTRIBUTORS}} BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
// IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Taken entirely from
// https://github.com/aldrin/home/blob/master/code/c++/crypto/crypto.h
// and munged to fit.
//
// Requires OpenSSL 1.0.0 or later, install one from brew on OSX.
//
// Some crypto advices:
// http://security.stackexchange.com/questions/2202/
//
#pragma once

#include "krypto/krypto.h"
#include <crypto_secretbox_xsalsa20poly1305.h>
// crypto_secretbox_aes256gcm is in todo list but is less secure wrt nonce generation

namespace crypto {

/// Provides authenticated encryption (xsalsa20poly1305)
class cipher : boost::noncopyable
{
    std::string key_;
    std::string nonce_;
    bool encrypt_;

public:
    /// Encryption mode  constructor, only takes key  and IV parameters.  Initializes the instance
    /// for encryption. The  key should be 128  bit (since we're with AES-128).  Typically, the IV
    /// should be 128 bit IV too but GCM supports  other IV sizes, so those can be passed to.
    /// @param key (input) container holding 128 key bits (use crypto::block)
    /// @param iv  (input) container holding 128 initialization vector bits (use crypto::block)
    template<typename K, typename I>
    cipher(const K &key, const I &iv): encrypt_(true)
    {
        initialize(boost::asio::buffer(key), boost::asio::buffer(iv));
    }

    /// Decryption  mode constructor,  takes key,  IV and  the authentication  tag  as parameters.
    /// Initializes  the cipher  for  decryption and  sets  the passed  tag  up for  authenticated
    /// decryption. The key  and IV should be the  same that were used to  generate the ciphertext
    /// you're trying to decrypt (obviously). The seal parameter should contain the authentication
    /// tag returned by the 'seal' call after encryption.
    /// @param key  (input) container holding 128 key bits (use crypto::block)
    /// @param iv   (input) container holding 128 initialization vector bits (use crypto::block)
    /// The seal parameter does not have a 'const' with it because of the OpenSSL API.
    /// @param seal (input) container holding 128 authentication tag bits (use crypto::block)
    template<typename K, typename I, typename S>
    cipher(const K &key, const I &iv, S &seal): encrypt_(false)
    {
        initialize(boost::asio::buffer(key), boost::asio::buffer(iv));
        internal::raw<void *> t(boost::asio::buffer(seal));
        internal::api("set tag", EVP_CIPHER_CTX_ctrl(&context_, EVP_CTRL_GCM_SET_TAG, t.len, t.ptr));
    }

    /// The  cipher transformation  routine. This  encrypts or  decrypts the  bytes from  the 'in'
    /// buffer and places them into the 'out'  buffer.  Since GCM does not require any padding the
    /// output buffer size  should be the same  as the input.  If you  have unencrypted associated
    /// data that must be added using 'associate_data' first.
    /// @param input  (input)  plaintext or ciphertext (for encryption or decryption resp.)
    /// @param output (output) inverse of the input
    template<typename I, typename O>
    cipher &transform(const I &input, O &output)
    {
        int outl;
        internal::raw<unsigned char *> out(boost::asio::buffer(output));
        internal::raw<const unsigned char *> in(boost::asio::buffer(input));
        internal::api("transform", EVP_CipherUpdate(&context_, out.ptr, &outl, in.ptr, in.len));
        return *this;
    }

    /// Adds associated authenticated data, i.e. data which is accounted for in the authentication
    /// tag, but  is not encrypted.  Typically, this  is used for  associated meta data  (like the
    /// packet header in a network protocol). This data must be added /before/ any message text is
    /// added to the cipher.
    /// @param aad (input) container with associated data
    template<typename A>
    cipher &associate_data(const A &aad)
    {
        internal::raw<const unsigned char *>a(boost::asio::buffer(aad));
        if (a.len > 0)
        {
            int outl;
            internal::api("associated data", EVP_CipherUpdate(&context_, nullptr, &outl, a.ptr, a.len));
        }
        return *this;
    }

    /// The encryption finalization routine. Populates  the authentication tag "seal" that must be
    /// passed  along for successful decryption. Any modifications in the cipher text or the
    /// associated data will be detected by the decryptor using this seal.
    /// @param seal (output) container to be populated with the tag bits.
    template<typename S>
    void seal(S &seal)
    {
        int outl;
        assert(encrypt_);
        internal::raw<void *> t(boost::asio::buffer(seal));
        internal::api("seal", EVP_CipherFinal_ex(&context_, nullptr, &outl));
        internal::api("get tag", EVP_CIPHER_CTX_ctrl(&context_, EVP_CTRL_GCM_GET_TAG, t.len, t.ptr));
    }

    /// The decryption finalization routine. Uses the authentication tag to verify if the
    /// decryption was successful. If the tag verification fails an exception is thrown,
    /// if all is well, the method silently returns. If an exception is thrown, the decrypted
    /// data is corrupted and *must* not be used.
    void verify()
    {
        int outl;
        assert(!encrypt_);
        internal::api("verify", EVP_CipherFinal_ex(&context_, nullptr, &outl));
    }

    ~cipher()
    {
        EVP_CIPHER_CTX_cleanup(&context_);
    }
private:
    bool encrypt_;
    EVP_CIPHER_CTX context_;
    void initialize(boost::asio::const_buffer k, boost::asio::const_buffer i)
    {
        EVP_CIPHER_CTX_init(&context_);
        internal::raw<const unsigned char *>iv(i);
        internal::raw<const unsigned char *>key(k);
        internal::api("initialize - i",
                      EVP_CipherInit_ex(&context_, EVP_aes_128_gcm(), nullptr, nullptr, nullptr, encrypt_));
        internal::api("set iv length",
                      EVP_CIPHER_CTX_ctrl(&context_, EVP_CTRL_GCM_SET_IVLEN, iv.len, nullptr));
        internal::api("initialize - ii",
                      EVP_CipherInit_ex(&context_, nullptr, nullptr, key.ptr, iv.ptr, encrypt_));
    }
};

} // crypto namespace
