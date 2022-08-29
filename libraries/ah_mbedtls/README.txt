/** @dir

Arrowhead Core MbedTLS TLS integration.

Transport Layer Security (TLS) is an important suite of standards used to form
secure connections over untrusted media. It makes up part of what could be
considered the foundation of the modern World Wide Web by being the security
aspect of the HTTPS protocol. It is ubiquitous also in other areas, much due to
the fact that standardizing and developing reliable cryptographic utilities is
very difficult and costly.

TLS can make use of the X.509 certificate standard for host identification,
which is one important reason why TLS has become very prominent within the
Arrowhead ecosystem.

This library provides an ah_tcp_trans implementation relying on MbedTLS, an open
source implementation of TLS that targets both embedded platforms and more
capable such. The functions provided by this library can be used to associate
a certificate, private key and store of trusted root certificates with an
ah_tcp_conn or ah_tcp_listener, either of which can be used as normal after such
an association is successful. This library does not hide MbedTLS in any way,
which means that it is up to you to configure the library as you like.

@see https://tls.mbed.org/

*/