(declare-project
    :name "openssl-hash"
    :description "Janet binding to hash functions provided by OpenSSL")

(declare-native
    :name "openssl-hash"
    :lflags ["-lssl" "-lcrypto"]
    :source ["openssl-hash.c"])