//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <openssl/dsa.h>
#include "krypto/sign_key.h"

namespace crypto {

class dsa160_key : public sign_key
{
    DSA* dsa_;

    dsa160_key(DSA* dsa);

public:
    dsa160_key(byte_array const& key);
    dsa160_key(int bits = 0);
    ~dsa160_key();

    byte_array id() const override;

    byte_array public_key() const override;
    byte_array private_key() const override;

    byte_array sign(byte_array const& digest) const override;
    bool verify(byte_array const& digest, byte_array const& signature) const override;

private:
    void dump() const;
};

} // crypto namespace
