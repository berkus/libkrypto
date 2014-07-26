add_library(krypto STATIC
    aes_128_ctr.cpp
#    aes_256_cbc.cpp
    sign_key.cpp
    rsa160_key.cpp
    dsa160_key.cpp
    utils.cpp)
