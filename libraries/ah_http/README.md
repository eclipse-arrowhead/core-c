@dir ah_http

## Arrowhead Core HTTP Library

The HyperText Transfer Protocol (HTTP) is a file-transfer protocol made famous
due to its key role in facilitating the World Wide Web (WWW). It is designed to
allow for web browsers and web servers to negotiate about and transfer the files
that make up the websites of the WWW. Over time, the protocol has also become a
popular foundation for other kinds of network-facing application interfaces, not
the least because of the rise in prevalence of asynchronous JavaScript on the
WWW. Due to its popularity, a great number of tools and libraries support it,
and a lot of developers have experience building applications on it.

For the mentioned reasons and other, HTTP currently has an important place in
the Arrowhead ecosystem. However, in contrast to the user-centric use case of
the WWW, the Arrowhead framework is primarily designed to facilitate
communication within machine-centric systems-of-systems. As a consequence, HTTP
is mainly used within the Arrowhead ecosystem as a foundation making Remote
Procedure Calls (RPCs), especially by implementing services as so-called RESTful
APIs. Making RPCs only require a fraction of the functionality needed to handle
all the nuances and complexities of the now quite extensive suite of WWW
standards, which means that much of HTTP is out of scope for many, if not most,
Arrowhead use cases.

The Arrowhead Core C libraries are designed to make it possible to run Arrowhead
systems on relatively constrained devices, and much of the HTTP specification
is, as we just established, out of scope for Arrowhead primarily focusing on
machine-to-machine interactions. Consequently, it becomes paramount that this
particular library strikes a good balance between HTTP conformance, small memory
and CPU footprint, as well as making it convenient to make HTTP RPCs. For these
reasons, this library provides utilities for parsing and, to a lesser extent,
generating HTTP request lines, status lines, headers, chunks and trailers, as
well as help handle a minimal set of headers (described further in
include/ah/http.h). Any functionality a particular application needs beyond this
minimal set can be implemented on top of this library, which means that complete
HTTP conformance remains a theoretical possibility despite its humble scope.
