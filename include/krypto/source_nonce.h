#pragma once

#include <sodiumpp/sodiumpp.h>

/// Class wrapping a received nonce for unboxing
/// @todo Match with newer implementation of nonce in sodiumpp
template <unsigned int constantbytes>
class source_nonce
{
private:
    std::string bytes;

public:
    static_assert(constantbytes == crypto_box_NONCEBYTES, "constantbytes needs to be equal to crypto_box_NONCEBYTES");

    source_nonce(const std::string& constant, bool = false)
        : bytes(constant)
    {
        if (constant.size() != constantbytes) {
            throw "constant bytes do not have correct length";
        }
    }
    std::string next()
    {
        return get();
    }
    std::string get() const
    {
        return bytes;
    }
    std::string constant() const { return bytes; }
    std::string sequential() const { return ""; }
};

template <unsigned int constantbytes>
std::ostream& operator<<(std::ostream& s, source_nonce<constantbytes> n)
{
    s << bin2hex(n.constant());
    return s;
}
