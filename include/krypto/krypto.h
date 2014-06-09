#pragma once

#include <stdexcept>
#include <boost/tr1/array.hpp>
#include <boost/utility.hpp>
#include <boost/asio/buffer.hpp>
#include <sodium/randombytes.h>

namespace crypto {

// Couple of sst-induced constants
enum {
    // Length of symmetric key material for HMAC-SHA-256-128
    HMACKEYLEN = 32,
    // We use SHA-256 or SHA-512-256 hashes for HMAC generation
    HMACLEN    = 32,
    SHA256_HASH_LEN = 32
};

namespace internal {

/// Check return values from OpenSSL and throw an exception if it failed.
/// @param what the logical operation being performed
/// @param ret the return value from OpenSSL API
inline void api(const char *what, int ret)
{
    if (ret == 0)
    {
        std::string message(what);
        message += " failed.";
        throw std::runtime_error(message);
    }
}
/// Internal representation of a raw buffer. Uses boost::asio::buffer to translate the passed
/// container to a raw pointer and length pair.
template<typename T>
struct raw
{
    T ptr;
    int len;
    template<typename B>
    raw(const B &b) : ptr(boost::asio::buffer_cast<T>(b)),
        len(static_cast<int>(boost::asio::buffer_size(b)))
    {}
};

} // internal namespace

/// Remove sensitive data from the buffer
/// Based on http://netbsd.2816.n7.nabble.com/Adding-memset-s-function-td43349.html
template<typename C>
void cleanse(C &c)
{
    /*
     * memset_volatile is a volatile pointer to the memset function.
     * You can call memset_volatile(buf, val, len) just as you would call
     * memset(buf, val, len), but the use of a volatile pointer
     * guarantees that the compiler will not optimise the call away.
     */
    void* (*volatile memset_volatile)(void *, int, size_t) = memset;
    internal::raw<void *> r(boost::asio::buffer(c));
    memset_volatile(r.ptr, 0, r.len);
}

/// A convenience typedef for a 128 bit block.
typedef boost::array<unsigned char, 16> block;

/// Fills the passed container with random bytes.
/// @param c  (output) container populated with random bits
template<typename C>
void fill_random(C &c)
{
    internal::raw<unsigned char *> r(boost::asio::buffer(c));
    randombytes_buf(r.ptr, r.len);
}

/// Derives a key from a password and salt using PBKDF2 with HMAC-SHA256 as the chosen PRF.
/// Although the routine can generate arbitrary length keys, it is best to use crypto::block as
/// the type for the key parameter, since it fixes the key length to 128 bit which is what the
/// other primitives in the wrapper (crypto::hash, crypto::cipher) require.
/// @param key      (output) container populated with the key bits
/// @param pass     (input)  container holding the user password
/// @param salt     (input)  container holding the salt bytes
/// @param c        (input)  PBKDF2 iteration count (default=10000)
template <typename C1, typename C2, typename C3>
void derive_key(C3 &key, const C1 &pass, const C2 &salt, int c = 10000)
{
    internal::raw<const char *> p(boost::asio::buffer(pass));
    internal::raw<unsigned char *> k(boost::asio::buffer(key));
    internal::raw<const unsigned char *> s(boost::asio::buffer(salt));
    internal::api("key derivation",
                  PKCS5_PBKDF2_HMAC(p.ptr, p.len, s.ptr, s.len, c, EVP_sha256(),
                                    k.len, k.ptr));
}

} // crypto namespace
