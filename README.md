# janet-openssl-hash

This library provides bindings to the `EVP_Digest` functionality of OpenSSL, which enables cryptographic hash functions to be used in Janet code.

## Usage

The package can be installed via the `jpm` utility, given that OpenSSL 1.1 or higher is installed (including headers, so use the -dev/-devel package if available).

There are three functions:

`(openssl-hash/new algorithm-name)`
Returns a new hasher instance with the given algorithm, or returns an error if the algorithm name is invalid. A list of algorithm names available on your system may be found using the command `openssl list -digest-algorithms`.

`(openssl-hash/feed hasher & data)`
Hashes `data` in sequential order. Data may be composed of any object that can be turned into a byte view, including strings and buffers.

`(openssl-hash/finalize hasher &opt flag)`
Returns the hash value of the hasher as a binary string. Once a hasher object has had finalize called on it MUST NOT be used again. Passing the value `:hex` as the flag argument will cause the result to be converted to hexadecimal ASCII.

## Example

```janet
(def my-hasher (openssl-hash/new "SHA256"))
(openssl-hash/feed my-hasher "hello world")
(print (openssl-hash/finalize my-hasher :hex))
```