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

/// Provides authenticated encryption (AES-128-GCM)
class cipher : boost::noncopyable
{
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
