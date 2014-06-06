#include "krypto/crypto_box_sign.h"

namespace crypto {

nacl_sign_key::nacl_sign_key()
{
    pk = crypto_sign_edwards25519sha512batch_keypair(&sk);
}

// public_key,flag[,private_key]
nacl_sign_key::nacl_sign_key(byte_array const& keys)
{
    keys >> pk >> has_sk;
    if (has_sk) {
        keys >> sk;
    }
}

nacl_sign_key::~nacl_sign_key()
{
    cleanse(sk);
    cleanse(pk);
}

byte_array nacl_sign_key::id() const
{
    assert(type() != invalid);
    return byte_array(sha256::hash(public_key()));
}

byte_array nacl_sign_key::public_key() const {
    return pk;
}

byte_array nacl_sign_key::private_key() const {
    return sk;
}

byte_array nacl_sign_key::sign(byte_array const& digest) const
{
    return byte_array(crypto_sign_edwards25519sha512batch_sign(digest, sk));
}

bool nacl_sign_key::verify(byte_array const& digest, byte_array const& signature) const
{
    // duh!
    crypto_sign_edwards25519sha512batch_open(signature, pk);
}

void nacl_sign_key::dump() const
{}

} // crypto namespace
