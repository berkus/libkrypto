# This needs to be sprinkled with BOOST_CHECK()s.
create_test(crypto LIBS support ${OPENSSL_LIBRARIES})
create_test(aes_128_ctr LIBS krypto support ${OPENSSL_LIBRARIES})
