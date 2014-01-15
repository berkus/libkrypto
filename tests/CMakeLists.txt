# This needs to be sprinkled with BOOST_CHECK()s.
create_test(crypto LIBS arsenal ${OPENSSL_LIBRARIES})
create_test(aes_128_ctr LIBS krypto arsenal ${OPENSSL_LIBRARIES})
