//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <openssl/sha.h>
#include <openssl/err.h>
#include "krypto/sha256_hash.h"
#include "krypto/rsa160_key.h"
#include "krypto/utils.h"
#include "krypto/krypto.h"
#include "arsenal/byte_array.h"
#include "arsenal/byte_array_wrap.h"
#include "arsenal/flurry.h"
#include "arsenal/logging.h"

namespace crypto {

rsa160_key::rsa160_key(RSA *rsa)
    : rsa_(rsa)
{}

rsa160_key::rsa160_key(byte_array const& key)
{
    rsa_ = RSA_new();
    assert(rsa_);

    byte_array_iwrap<flurry::iarchive> read(key);
    bool has_private_key;

    read.archive() >> rsa_->n >> rsa_->e >> has_private_key;
    if (has_private_key) {
        read.archive() >> rsa_->d >> rsa_->p >> rsa_->q >> rsa_->dmp1 >> rsa_->dmq1 >> rsa_->iqmp;
    }

    if (has_private_key)
        set_type(public_and_private);
    else
        set_type(public_only);
}

rsa160_key::rsa160_key(int bits, unsigned e)
{
    if (bits == 0) {
        bits = 2048;
    }
    if (e == 0) {
        e = 65537;
    }
    if (!(e % 2)) {
        ++e; // e must be odd
    }

    // Generate a new RSA key given those parameters
    rsa_ = RSA_generate_key(bits, e, nullptr, nullptr);

    assert(rsa_);
    assert(rsa_->d);

    set_type(public_and_private);
}

rsa160_key::~rsa160_key()
{
    if (rsa_) {
        RSA_free(rsa_);
        rsa_ = nullptr;
    }
}

byte_array
rsa160_key::id() const
{
    assert(type() != invalid);

    crypto::hash::value hash = sha256::hash(public_key());

    byte_array id(hash);
    // Only return 160 bits of key identity information,
    // because this method's security may be limited by the SHA-1 hash
    // used in the RSA-OAEP padding process.
    id.resize(160/8);

    return id;
}

byte_array
rsa160_key::public_key() const
{
    assert(type() != invalid);
    byte_array data;
    {
        byte_array_owrap<flurry::oarchive> write(data);
        // Write the public part of the key
        write.archive() << rsa_->n << rsa_->e << false;
    }
    return data;
}

byte_array
rsa160_key::private_key() const
{
    assert(type() == public_and_private);
    byte_array data;
    {
        byte_array_owrap<flurry::oarchive> write(data);
        // Write the public and private parts of the key
        write.archive() << rsa_->n << rsa_->e << true;
        write.archive() << rsa_->d << rsa_->p << rsa_->q << rsa_->dmp1 << rsa_->dmq1 << rsa_->iqmp;
    }
    return data;
}

byte_array
rsa160_key::sign(byte_array const& digest) const
{
    assert(type() != invalid);
    assert(digest.size() == SHA256_DIGEST_LENGTH);

    byte_array signature;
    unsigned siglen = RSA_size(rsa_);
    signature.resize(siglen);

    if (!RSA_sign(NID_sha256,
            (unsigned char*)digest.data(), SHA256_DIGEST_LENGTH,
            (unsigned char*)signature.data(), &siglen, rsa_))
    {
        logger::fatal() << "RSA signing error - " << ERR_error_string(ERR_get_error(), nullptr);
    }

    assert(siglen <= signature.size());
    signature.resize(siglen);

    return signature;
}

bool
rsa160_key::verify(byte_array const& digest, byte_array const& signature) const
{
    assert(type() != invalid);
    assert(digest.size() == SHA256_DIGEST_LENGTH);

    int rc = RSA_verify(NID_sha256,
            (unsigned char*)digest.data(), SHA256_DIGEST_LENGTH,
            (unsigned char*)signature.const_data(), signature.size(), rsa_);

    if (!rc)
    {
        logger::warning() << "RSA signature verification failed - " << ERR_error_string(ERR_get_error(), nullptr);
    }

    return rc == 1;
}

void
rsa160_key::dump() const
{}

} // crypto namespace
