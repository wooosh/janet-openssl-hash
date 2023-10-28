(declare-project
    :name "openssl-hash"
    :description "Janet binding to hash functions provided by OpenSSL"
    :author "wooosh"
    :license "MIT"
    :url "https://github.com/wooosh/janet-openssl-hash"
    :repo "https://github.com/wooosh/janet-openssl-hash")

(declare-native
    :name "openssl-hash"
    :lflags ["-lcrypto"]
    :source ["openssl-hash.c"])