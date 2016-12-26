#pragma once

/// Class representing a randomly generated nonce with fixed prefix
/// @todo Match with newer implementation of nonce in sodiumpp
template <unsigned int constantbytes>
class random_nonce
{
private:
    std::string bytes;

public:
    static_assert(constantbytes < crypto_box_NONCEBYTES, "constantbytes needs to be less than crypto_box_NONCEBYTES");

    random_nonce(const std::string& constant, bool = false)
        : bytes(constant)
    {
        if (constant.size() != constantbytes) {
            throw "constant bytes do not have correct length";
        }
        bytes.resize(crypto_box_NONCEBYTES, 0);
        randombytes_buf(&bytes[constantbytes], crypto_box_NONCEBYTES - constantbytes);
    }
    std::string next()
    {
        return get();
    }
    std::string get() const
    {
        return bytes;
    }
    std::string constant() const { return bytes.substr(0, constantbytes); }
    std::string sequential() const { return bytes.substr(constantbytes, crypto_box_NONCEBYTES - constantbytes); }
};

template <unsigned int constantbytes>
std::ostream& operator<<(std::ostream& s, random_nonce<constantbytes> n)
{
    s << bin2hex(n.get());
    return s;
}
