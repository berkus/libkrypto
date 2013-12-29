/// Copyright (c) 2013, Aldrin's Notebook.
/// http://opensource.org/licenses/BSD-2-Clause
#define BOOST_TEST_MODULE Test_aes_128_ctr
#include <boost/test/unit_test.hpp>

#include "krypto.h"
#include "aes_128_ctr.h"

BOOST_AUTO_TEST_CASE(encode_then_decode)
{
    BOOST_CHECK(crypto::prng_ok());                            // check PRNG state
    std::vector<char> vec(16);                                 // use a std::vector
    crypto::fill_random(vec);                                  // fill it with random bytes

    crypto::aes_128_ctr aes(vec);

    byte_array text{"Mary had a little lamb"};
    byte_array previously_encrypted;

    for (int i = 0; i < 16; ++i)
    {
        union {
            uint64_t words[2];
            boost::array<uint8_t, AES_BLOCK_SIZE> bytes;
        } iv;

        iv.words[0] = i;
        iv.words[1] = 0;

        byte_array encrypted = aes.encrypt(text, iv.bytes);

        byte_array decrypted = aes.decrypt(encrypted, iv.bytes);

        BOOST_CHECK(previously_encrypted != encrypted);
        BOOST_CHECK(text.size() == decrypted.size());
        BOOST_CHECK(std::equal(text.begin(), text.end(), decrypted.begin()));

        previously_encrypted = encrypted;
    }

    crypto::cleanse(vec);                                      // clear sensitive data
}
