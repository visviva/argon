# OpenSSL DTLS Echo Server
[![C/C++ CI](https://github.com/visviva/argon/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/visviva/argon/actions/workflows/c-cpp.yml)

This is just a quick hackup for a DTLS echo server using openssl 1.0.2. It works but MTU settings are completely ignored for the moment.
For whatever reason `valgrind` is also crashing in some random libuv function.

Usage:
```bash
$ mkdir build
$ cd build
$ conan install ..
$ source ./activate.sh
$ cmake ..
$ make
$ ./argon
```

In another shell you can start the openssl s_client:
```bash
$ openssl s_client -dtls1_2 -connect 127.0.0.1:8888 -cert ../keys/client-cert.pem -key ../keys/client-key.pem -CAfile ../keys/ca-cert.pem -cipher DEFAULT
```

Keys and certificates are provided and can be used. If there is a need to change them, [here](https://mariadb.com/docs/ent/security/data-in-transit-encryption/create-self-signed-certificates-keys-openssl/) is a good source on how to create them.
