    @dir ah_mbedtls @brief MbetTLS integration library.

Transport Layer Security (TLS) is an important suite of standards used to form
secure connections over untrusted media. It makes up part of what could be
considered the foundation of the modern World Wide Web by being the security
aspect of the HTTPS protocol. It is ubiquitous also in other areas, much due to
the fact that standardizing and developing reliable cryptographic utilities is
very difficult and costly.

TLS can make use of the X.509 certificate standard for host identification,
which is one important reason why TLS has become very prominent within the
Arrowhead ecosystem.

This library provides an ah_tcp_trans implementation relying on [MbedTLS][mbed],
an open  source implementation of TLS that targets both embedded platforms and
more capable such. The functions provided by this library can be used to
associate a certificate, private key and store of trusted root certificates with
an ah_tcp_conn or ah_tcp_listener, either of which can be used as normal after
such an association is successful. This library does not hide MbedTLS in any
way, which means that it is up to you to configure the library as you like.

[mbed]: https://tls.mbed.org/

### Dependencies

Building this library requires MBedTLS version 2.28.0 or later, or version 3.1.0
or later. If you have a working Internet connection, CMake will attempt to
download and compile a suitable version of the library automatically. If,
however, any version of MBedTLS is already installed and available on your
system, that version will be used without any download being initiated.
__Please note, however, that relying on automatically downloaded MBedTLS__
__versions can be a security hazard.__ New versions of MBedTLS often contain
patches for discovered security vulnerabilities. The automatically downloaded
version may not contain all relevant patches nor satisfy other security
requirements you may have. The safe use of this library requires you to have
access to properly reviewed, configured and managed versions of MBedTLS. Please
get in contact with a security consultancy with MBedTLS experience if you do not
have access to that competence yourself.
