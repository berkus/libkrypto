//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <openssl/sha.h>
#include "crypto/sha256_hash.h"
#include "crypto/dsa160_key.h"
#include "crypto/utils.h"
#include "crypto.h"
#include "byte_array.h"
#include "byte_array_wrap.h"
#include "flurry.h"
#include "logging.h"

namespace ssu {
namespace crypto {

/*
 * The DSA parameter sets have been taken unaltered
 * from SST implementation in Netsteria.
 */

// The three DSA parameter sets were generated according to the key length recommendations
// in NIST Special Publication 800-57, April 2005 DRAFT - except that the length of the
// prime divisor q is always 160 bits because this is the only length OpenSSL currently supports.
// ** This is a bug and should be fixed in a future ID scheme. **
namespace {

DSA *get_dsa1024()
{
    /*** DSA parameters for generating 1024-bit DSA keys ***/
    static unsigned char dsa1024_p[]={
        0xAA,0x55,0xCE,0xCE,0x1D,0xFC,0x45,0x31,0xE2,0x12,0x67,0xC9,
        0xD3,0x20,0x97,0x77,0xE6,0x65,0xB4,0x85,0xBB,0xAB,0x13,0xD6,
        0x93,0x00,0xBC,0x4C,0xF4,0x9E,0x20,0xD1,0x4A,0xE9,0xBD,0x20,
        0x96,0x0D,0xBF,0x2E,0xAB,0x27,0xE1,0x28,0xFB,0x0C,0x3E,0xFF,
        0x9E,0x37,0x7B,0x94,0xCE,0x00,0xC2,0x31,0x61,0x35,0x2D,0x00,
        0x9D,0x28,0xA9,0xB8,0xEF,0x34,0x0D,0x1B,0x55,0xB8,0x7E,0xD9,
        0x75,0x0E,0xF6,0x87,0x82,0x25,0xA1,0x29,0x70,0x59,0x4B,0x0D,
        0x52,0x8C,0x89,0xCD,0xA8,0xCA,0xE8,0x8D,0xBD,0x6F,0x64,0xD6,
        0x8B,0xA1,0x2B,0x4F,0xD8,0x86,0x12,0xB3,0x03,0x1A,0xA6,0xA1,
        0x8D,0x11,0xFF,0x44,0x1D,0x28,0x38,0x76,0xCB,0xAD,0xF8,0x46,
        0x76,0xC2,0x03,0x02,0x55,0x4E,0xE4,0x6D,
        };
    static unsigned char dsa1024_q[]={
        0xE5,0xB1,0x97,0x79,0x69,0xB1,0xA1,0x79,0xD5,0xA5,0x44,0xDA,
        0xC9,0xAC,0x5C,0xA1,0x2D,0x98,0xE1,0xA5,
        };
    static unsigned char dsa1024_g[]={
        0x25,0x7A,0x83,0x4E,0x65,0xB2,0x0C,0x22,0x75,0x3B,0x33,0xA2,
        0x46,0x87,0xAE,0xF3,0xF5,0xB1,0xDE,0x31,0xE2,0x30,0x17,0xC8,
        0x74,0x53,0x24,0x0E,0x44,0x96,0xBF,0xFD,0xB6,0x15,0xF8,0xDD,
        0x40,0x2E,0xE2,0xD2,0x38,0x3E,0xA1,0xFB,0xBC,0x75,0xF9,0x28,
        0xF9,0xBC,0xAE,0x11,0x16,0xF0,0x47,0x05,0xD9,0x07,0x21,0x10,
        0xFF,0xA2,0x38,0xF0,0x61,0x8B,0x0B,0x16,0x20,0xFB,0x0A,0x2F,
        0x2D,0x1C,0xF2,0x97,0xCC,0x05,0xC7,0xF9,0x3B,0x7E,0xB7,0x12,
        0xC1,0x50,0x65,0x2F,0x54,0xAA,0x7B,0x1A,0x68,0xC1,0x3A,0xE0,
        0x21,0xDA,0xAC,0x7F,0xC2,0x05,0x16,0x28,0xCE,0xF8,0xAF,0x4B,
        0x3C,0x83,0xCF,0x61,0xB9,0xED,0xC5,0x69,0x87,0x7B,0x02,0xC5,
        0xAD,0xF5,0xF0,0xB2,0x9B,0xD5,0x83,0x5E,
        };

    DSA *dsa{0};

    if ((dsa = DSA_new()) == nullptr) return nullptr;
    dsa->p = BN_bin2bn(dsa1024_p, sizeof(dsa1024_p), nullptr);
    dsa->q = BN_bin2bn(dsa1024_q, sizeof(dsa1024_q), nullptr);
    dsa->g = BN_bin2bn(dsa1024_g, sizeof(dsa1024_g), nullptr);
    if ((dsa->p == nullptr) || (dsa->q == nullptr) || (dsa->g == nullptr))
    {
        DSA_free(dsa);
        return nullptr;
    }
    return dsa;
}

DSA *get_dsa2048()
{
    /*** DSA parameters for generating 2048-bit DSA keys ***/
    static unsigned char dsa2048_p[]={
        0xBF,0xEE,0xBC,0x73,0xC2,0x0D,0x28,0xDD,0x5E,0xE1,0x34,0x5B,
        0xA4,0x32,0xB2,0x02,0xF4,0x4F,0xF4,0x53,0x42,0x30,0x6D,0xB6,
        0x4D,0xCC,0xBE,0xB7,0x21,0xC3,0xEC,0x09,0xFB,0xC4,0x0A,0xC5,
        0x65,0x92,0xD1,0xFB,0x3F,0xF9,0x05,0x7D,0x0D,0xF6,0x73,0xC3,
        0xDA,0x73,0x62,0x77,0x40,0x55,0x25,0x39,0xB6,0x39,0x4B,0xAC,
        0x40,0x26,0xD7,0xCA,0x85,0x48,0xA8,0x9A,0xB1,0x98,0x09,0x9A,
        0xF5,0xD8,0x74,0xD0,0x0F,0x50,0xFC,0x25,0xC2,0xB0,0xDD,0xE1,
        0xB2,0xFB,0x28,0xCC,0x35,0x09,0xCF,0x0C,0x37,0x71,0x91,0x12,
        0x48,0x37,0x34,0x2D,0x7F,0xB8,0x81,0xFA,0x06,0xF8,0x59,0x5E,
        0x9F,0x9E,0x92,0x6A,0xB3,0xC9,0x67,0x7F,0x73,0x80,0xA9,0x25,
        0xB9,0x1A,0x70,0x9F,0xA6,0x44,0x7B,0x81,0x34,0x57,0x95,0xF2,
        0xB9,0x8A,0x30,0x55,0x83,0x14,0x96,0x77,0x71,0x26,0x50,0xDB,
        0x70,0xF9,0x5A,0x54,0x3D,0xAD,0xB7,0x78,0xA8,0x33,0xEC,0x7D,
        0x48,0xF5,0x97,0xCA,0x35,0xC0,0x11,0x03,0xCA,0x2E,0xE7,0x16,
        0x32,0xDB,0x02,0xBC,0x42,0x16,0x27,0xD8,0x55,0x35,0xEB,0x2A,
        0x68,0xF2,0x28,0x71,0xE5,0xF2,0x6D,0xAE,0x19,0x62,0xA8,0xDF,
        0x3C,0xEC,0xC4,0x6F,0x08,0x18,0x59,0x35,0x36,0x1E,0x12,0x75,
        0x37,0xE7,0xF6,0x36,0x4D,0x3D,0xB9,0x77,0x97,0x84,0x11,0xB0,
        0xB1,0xED,0x2F,0xC6,0x71,0x68,0xA4,0x6A,0xDE,0x35,0x8F,0x58,
        0xF1,0xAD,0xCB,0x3F,0x4E,0x1E,0x31,0x58,0xFB,0xBB,0xB8,0x07,
        0x4C,0x5D,0x23,0xF1,0x94,0x7A,0x38,0xD7,0xE1,0x4B,0x35,0x40,
        0xFF,0xDF,0x9F,0xBF,
        };
    static unsigned char dsa2048_q[]={
        0xFF,0xFA,0x33,0xE9,0x01,0xE6,0x59,0xBC,0x61,0x34,0xC4,0xDB,
        0x29,0xB6,0x59,0x85,0x0D,0xDA,0x40,0x7F,
        };
    static unsigned char dsa2048_g[]={
        0x48,0xDF,0x41,0xEA,0x7A,0xAC,0x8C,0x28,0x89,0x42,0xE0,0x5E,
        0x86,0xE8,0xB0,0xFD,0x70,0x69,0xF2,0x61,0x74,0x91,0x6D,0x16,
        0x92,0x06,0x67,0x18,0xC8,0x54,0xB6,0xD2,0xED,0x63,0x7F,0x76,
        0x1A,0xDD,0x5A,0xCB,0x54,0x2B,0x04,0x7B,0xDF,0x1A,0x43,0x50,
        0x08,0x66,0x41,0x5E,0xD0,0x9B,0xBF,0xC5,0xD0,0x62,0x32,0x94,
        0x68,0xDD,0x15,0xF8,0xC0,0xBA,0xDB,0xA1,0x47,0x94,0x7B,0x29,
        0x84,0xE1,0x9B,0x88,0x1C,0x63,0x22,0xD7,0x56,0x7E,0xB5,0x9F,
        0xD8,0xFB,0x16,0x7B,0x59,0x2D,0x0A,0xDE,0x51,0x1C,0x22,0x92,
        0xB0,0xA8,0x6E,0xA8,0x81,0xB6,0x2C,0x49,0xAE,0x4F,0x8C,0xCC,
        0x16,0xFF,0x2A,0x27,0x35,0x07,0xC5,0xD1,0xDB,0x6C,0xE3,0xFE,
        0x9F,0x3D,0x8F,0x8E,0x22,0x79,0xDA,0x6F,0x20,0xE1,0xB9,0x08,
        0x38,0xD3,0x49,0x03,0x7F,0xCD,0xAF,0xB6,0x54,0x7A,0x02,0xB1,
        0x92,0x8B,0xD6,0x23,0xA9,0x7F,0xC8,0xD1,0xB1,0x62,0x4E,0x82,
        0x6B,0xA1,0x55,0xCE,0x4D,0x09,0x9B,0x51,0x6D,0x6C,0x96,0x7B,
        0xA5,0xF1,0x21,0x0F,0x75,0x9B,0x3D,0x3C,0x3D,0x94,0x83,0x03,
        0x9F,0x6A,0xDE,0xC5,0x7F,0x3B,0x44,0xF9,0xF5,0x49,0xC8,0xCA,
        0x5D,0x60,0x04,0x67,0xDF,0x22,0xCC,0x9B,0xB4,0xA2,0x33,0x35,
        0xD4,0x85,0xC4,0xAD,0x4C,0xA0,0x3D,0x52,0x4B,0xF9,0xBA,0x47,
        0xD8,0xE9,0x90,0xD7,0x88,0x8B,0x25,0xC5,0xD7,0xA4,0x5B,0x4E,
        0xD0,0xA5,0x3B,0xAF,0x6B,0x49,0x3B,0x53,0xDB,0x61,0xB6,0x37,
        0xF3,0xE0,0xC8,0x3A,0xEB,0xB2,0x0A,0xAB,0x34,0xEF,0x75,0x50,
        0x1C,0xDB,0x67,0x75,
        };

    DSA *dsa{0};

    if ((dsa = DSA_new()) == nullptr) return nullptr;
    dsa->p = BN_bin2bn(dsa2048_p, sizeof(dsa2048_p), nullptr);
    dsa->q = BN_bin2bn(dsa2048_q, sizeof(dsa2048_q), nullptr);
    dsa->g = BN_bin2bn(dsa2048_g, sizeof(dsa2048_g), nullptr);
    if ((dsa->p == nullptr) || (dsa->q == nullptr) || (dsa->g == nullptr))
    {
        DSA_free(dsa);
        return nullptr;
    }
    return dsa;
}

DSA *get_dsa3072()
{
    /*** DSA parameters for generating 3072-bit DSA keys ***/
    static unsigned char dsa3072_p[]={
        0xF8,0xEB,0xBD,0xB4,0x42,0xC1,0xA9,0x56,0x75,0xEF,0x67,0xC9,
        0xFF,0xD3,0x37,0xCE,0xBF,0x06,0xC2,0x4D,0xEC,0xD5,0x2C,0x26,
        0xFF,0x7A,0xC0,0xC6,0x36,0x02,0xD4,0x42,0xF0,0x04,0xD5,0xCF,
        0x8B,0xB1,0x62,0x04,0x0D,0xFB,0x4E,0x93,0x65,0xAC,0x60,0x85,
        0x5E,0x54,0xAC,0xC6,0x9C,0x7E,0xF4,0x0A,0x37,0xD8,0x25,0x21,
        0x59,0x7B,0x46,0xCB,0x37,0xF7,0x9B,0x1F,0x5C,0x24,0x2F,0x49,
        0x4D,0x6F,0xED,0x4E,0xE8,0x1A,0xB1,0x39,0x60,0xDF,0x09,0xD2,
        0x37,0x98,0x46,0x74,0xB6,0x43,0x80,0x4D,0xD5,0xA4,0x38,0x9D,
        0xB1,0x66,0xE3,0x69,0xAC,0x87,0xC8,0x81,0x8A,0xDC,0xCE,0xDB,
        0x02,0x5F,0x82,0x0C,0xED,0xA6,0x89,0x77,0x67,0x73,0x9F,0xBA,
        0x23,0x8F,0xF4,0xA4,0xF7,0x88,0xB8,0xD4,0x7D,0x85,0x28,0xCD,
        0x85,0x9F,0xE3,0xE8,0x3B,0xD1,0xDD,0x4D,0x2C,0xE3,0xD0,0xEF,
        0x43,0x55,0x16,0x24,0xC5,0xB3,0x4D,0xCE,0xEB,0x73,0x13,0x41,
        0x38,0x63,0x6E,0x12,0x11,0x13,0x0A,0x31,0xBB,0xA7,0x54,0xF7,
        0x52,0x42,0xA1,0x39,0x72,0x53,0x56,0x8C,0xE9,0xAF,0x67,0x33,
        0xC5,0x2D,0x54,0x05,0xA0,0x5A,0x8C,0x42,0x34,0x68,0x1B,0x3D,
        0xBB,0x23,0x4B,0xDF,0xD3,0x84,0x47,0x59,0xBC,0xDC,0x07,0x73,
        0x18,0x5D,0xA4,0x5D,0xAC,0xC6,0x1E,0x6A,0xB0,0xD1,0xC7,0x8E,
        0xEC,0x3F,0x22,0x1F,0x1E,0x49,0xDD,0xA8,0xE3,0x1A,0x32,0x2D,
        0xED,0xBB,0x04,0x34,0x9D,0x34,0x38,0x11,0xB5,0xCD,0x6B,0x81,
        0xEB,0xF1,0x36,0xF1,0x6F,0xDA,0x41,0xB0,0x0D,0xD0,0x7E,0xAF,
        0x40,0xAB,0xC5,0x36,0x94,0xB4,0x9C,0x25,0x55,0x59,0x4C,0xA5,
        0x2F,0x1D,0x66,0xBD,0xB9,0xB5,0xF6,0x09,0x59,0xC4,0x33,0x53,
        0x92,0x5F,0x41,0xF8,0x7F,0x75,0xC6,0xD2,0x82,0x3C,0x4F,0x5D,
        0xF2,0xED,0x1A,0x10,0x66,0xD8,0x20,0x3E,0xFE,0x2A,0x99,0xB0,
        0x6A,0xE0,0x80,0xE1,0x53,0xEF,0x64,0xAD,0x1F,0xAC,0x23,0x92,
        0xB1,0xBF,0x1E,0x04,0x47,0xA0,0x2B,0x6B,0x2B,0xBA,0x88,0xC7,
        0x71,0x73,0xAD,0x0D,0xE1,0x64,0xAE,0xB1,0x74,0xB5,0x3A,0xE1,
        0xFF,0xF6,0x49,0x01,0xB6,0x76,0xB4,0xC9,0xA4,0xA7,0x52,0xF7,
        0xAB,0x93,0x2A,0x4E,0xBB,0xA5,0xC4,0x29,0xF7,0xD7,0xD0,0x78,
        0x39,0xC4,0x78,0x6B,0xD1,0x76,0xB0,0xAB,0x17,0xA2,0xD2,0x1F,
        0xFA,0x7C,0xAD,0xD0,0x92,0xF2,0x4F,0x27,0x2B,0x10,0x38,0xA7,
        };
    static unsigned char dsa3072_q[]={
        0xE0,0x01,0x84,0xE0,0x7A,0xE2,0x51,0xED,0x48,0x54,0x92,0x53,
        0x3F,0x56,0x3A,0x98,0x2D,0xC3,0x19,0x0B,
        };
    static unsigned char dsa3072_g[]={
        0xBA,0x4E,0x50,0x98,0x0D,0x5A,0x5B,0x5D,0xF2,0xB3,0xBD,0x6F,
        0x0E,0x80,0x53,0x58,0x03,0xE0,0xE0,0x88,0x45,0xF4,0x68,0xF7,
        0x7B,0x21,0x69,0x70,0xFC,0x74,0xFE,0x39,0x0A,0xF4,0xE7,0x0B,
        0xE8,0xAD,0x22,0x43,0xC3,0x58,0xC1,0xE5,0xCB,0x10,0x78,0xBD,
        0xBB,0xFF,0x58,0xF9,0xE0,0x5D,0xE3,0xAA,0xB3,0xF0,0x43,0x25,
        0x83,0xF3,0x7B,0x1D,0xC7,0xC1,0xC8,0x7B,0x41,0x75,0x3E,0xA6,
        0xF3,0xC5,0xD7,0x0A,0x79,0x72,0x4B,0x4A,0xCA,0x3A,0xBF,0x72,
        0xF2,0x1B,0xB5,0x5A,0x56,0x89,0xCA,0x67,0xFC,0x6A,0x27,0xC3,
        0xCE,0x5F,0x63,0x81,0x37,0x42,0x9B,0x91,0x69,0x84,0xB8,0x63,
        0x16,0xAE,0x44,0x10,0x02,0x15,0xCF,0xE6,0xE1,0xD6,0x9F,0x94,
        0x59,0x8C,0x6C,0x21,0xCA,0xCF,0x55,0x61,0x8F,0x87,0x30,0x85,
        0xA2,0xFA,0x9E,0x8C,0x6B,0x3F,0xEB,0xDB,0xF7,0xD7,0xC8,0xBC,
        0x1F,0x03,0x87,0x64,0x19,0x53,0x3B,0x21,0x90,0x82,0x9C,0xD7,
        0xA7,0xEC,0x1F,0x15,0x15,0x9A,0x5E,0x03,0x52,0x8F,0x09,0xC3,
        0xC7,0x77,0x87,0x0A,0x49,0x3A,0x63,0x31,0x3D,0x98,0xE2,0xB4,
        0xC7,0xFF,0x96,0x27,0xC8,0x22,0x8E,0xAF,0x47,0x8E,0x7E,0xB4,
        0x1C,0x03,0x6C,0x52,0x96,0x0C,0x5E,0x57,0xAC,0xD0,0x35,0xF6,
        0x1B,0xBE,0x60,0x81,0x97,0x97,0x47,0x8D,0xC8,0x9C,0xB9,0xD0,
        0x5A,0x69,0x98,0xF8,0xB6,0xDF,0x21,0x03,0x75,0xB3,0xE9,0xD2,
        0xD2,0xFE,0x5D,0xEF,0x36,0xA4,0x82,0x73,0x3C,0x96,0xC1,0xD1,
        0x74,0x21,0xD7,0x62,0x8B,0xE4,0x5A,0x24,0xC2,0xF1,0x82,0x8B,
        0xD4,0x21,0xA3,0x59,0xA7,0xF1,0x34,0x9C,0x0F,0x10,0xA8,0x37,
        0x66,0xCA,0x82,0x24,0xC3,0x1E,0xFE,0x94,0xE0,0xEB,0x94,0xB8,
        0x83,0x2F,0x36,0xB7,0xBB,0xD1,0x58,0x55,0x62,0x60,0xE9,0xE7,
        0xCE,0x27,0x00,0x5C,0x35,0xB0,0xE8,0x2B,0x77,0xBC,0xE4,0x37,
        0xF3,0xB2,0x26,0xB0,0xF6,0x49,0xCF,0x43,0x0D,0xC6,0x07,0x90,
        0x89,0x60,0x8B,0x71,0x09,0x25,0xD5,0xF4,0x89,0xFA,0x13,0x30,
        0x81,0x6C,0x31,0xE7,0x4B,0x38,0x71,0xAF,0x35,0x71,0x36,0x76,
        0x99,0x4A,0x3E,0xDD,0x24,0x5B,0xD7,0xC8,0x9F,0xA5,0x81,0x4E,
        0xB5,0x3F,0xBE,0xA4,0x00,0x0B,0x50,0x8B,0x81,0x3F,0x5C,0x48,
        0x06,0x0C,0xEE,0x52,0xFA,0x29,0xB1,0x0F,0xDF,0xA5,0x70,0x8D,
        0xD7,0x63,0x70,0xCC,0xA6,0xB2,0x70,0xCE,0x27,0x37,0x1D,0x04,
        };

    DSA *dsa{0};

    if ((dsa = DSA_new()) == nullptr) return nullptr;
    dsa->p = BN_bin2bn(dsa3072_p, sizeof(dsa3072_p), nullptr);
    dsa->q = BN_bin2bn(dsa3072_q, sizeof(dsa3072_q), nullptr);
    dsa->g = BN_bin2bn(dsa3072_g, sizeof(dsa3072_g), nullptr);
    if ((dsa->p == nullptr) || (dsa->q == nullptr) || (dsa->g == nullptr))
    {
        DSA_free(dsa);
        return nullptr;
    }
    return dsa;
}

} // anonymous namespace

dsa160_key::dsa160_key(DSA *dsa)
    : dsa_(dsa)
{}

dsa160_key::dsa160_key(byte_array const& key)
{
    assert(type() == invalid);

    dsa_ = DSA_new();
    assert(dsa_);

    byte_array_iwrap<flurry::iarchive> read(key);
    read.archive() >> dsa_->p >> dsa_->q >> dsa_->g >> dsa_->pub_key >> dsa_->priv_key;

    if (BN_num_bytes(dsa_->priv_key) > 0) {
        set_type(public_and_private);
    } else {
        set_type(public_only);
        BN_free(dsa_->priv_key);
        dsa_->priv_key = nullptr;
    }
}

dsa160_key::dsa160_key(int bits)
{
    if (bits == 0) {
        bits = 2048;
    }
    // Choose an appropriate set of DSA parameters for the new key.
    if (bits <= 1024) {
        dsa_ = get_dsa1024();
    }
    else if (bits <= 2048) {
        dsa_ = get_dsa2048();
    }
    else if (bits <= 3072) {
        dsa_ = get_dsa3072();
    }
    else {
        logger::fatal() << "Can't currently produce DSA keys with more than 3072 bits";
    }

    assert(dsa_);

    // Generate a new DSA key given those parameters
    int rc = DSA_generate_key(dsa_);
    assert(rc == 1);
    assert(dsa_->priv_key != nullptr);

    set_type(public_and_private);
}

dsa160_key::~dsa160_key()
{
    if (dsa_) {
        DSA_free(dsa_); // @todo Make dsa_ an unique_ptr<>?
        dsa_ = nullptr;
    }
}

byte_array 
dsa160_key::id() const
{
    assert(type() != invalid);

    crypto::hash::value hash = sha256::hash(public_key());

    byte_array id(hash);
    // Only use 160 bits of the hash to produce the ID,
    // because the cryptographic strength of the resulting ID
    // is limited anyway by the 160-bit digest size, below.
    // We're not using SHA-256 to get more than 160 bits of security,
    // but in hopes it will withstand the recent attacks against SHA-1.
    id.resize(160/8);

    return id;
}

byte_array
dsa160_key::public_key() const
{
    assert(type() != invalid);
    byte_array data;
    {
        byte_array_owrap<flurry::oarchive> write(data);
        // Write the public part of the key
        write.archive() << dsa_->p << dsa_->q << dsa_->g << dsa_->pub_key << byte_array();
    }
    return data;
}

byte_array
dsa160_key::private_key() const
{
    assert(type() == public_and_private);
    byte_array data;
    {
        byte_array_owrap<flurry::oarchive> write(data);
        // Write the public and private parts of the key
        write.archive() << dsa_->p << dsa_->q << dsa_->g << dsa_->pub_key << dsa_->priv_key;
    }
    return data;
}

byte_array
dsa160_key::sign(byte_array const& digest) const
{
    assert(type() == public_and_private);
    assert(digest.size() == SHA256_DIGEST_LENGTH);

    // The version of DSA currently implemented by OpenSSL only supports digests up to 160 bits.
    int digest_size = 160/8;

    DSA_SIG *sig = DSA_do_sign((const unsigned char*)digest.data(), digest_size, dsa_);
    assert(sig);

    byte_array signature;
    {
        byte_array_owrap<flurry::oarchive> write(signature);
        // write to signature
        write.archive() << sig->r << sig->s;
    }

    DSA_SIG_free(sig);

    return signature;
}

bool
dsa160_key::verify(byte_array const& digest, byte_array const& signature) const
{
    return false;
}

void
dsa160_key::dump() const
{}

} // crypto namespace
} // ssu namespace
