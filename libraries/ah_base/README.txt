/** @dir

Arrowhead Core C base library.

This library provides the foundation upon which most other Core C libraries
depend. It most significantly exposes a cross-platform API over some I/O
utilities provided by the targeted platforms, such as TCP/IP networking. Most of
the I/O operations exposed by this library are provided as asynchronous
functions, which is to say that their results are provided after they return by
invoking given callback functions. All asynchronous functionality of the library
is managed via so-called event loops (see include/ah/loop.h), which can be seen
as single-threaded event queues managed by this library.

As managing events require several kinds of peripheral functionality, some of
that is also exposed, or made configurable (see include/ah/conf.h), by this
library. Buffers, error codes, safe math functions and time querying are some
notable examples.

Another primary purpose of this library is to gather together key functionality
that must be ported in order for this and most other official Arrowhead Core C
libraries to support another platform. While there may be some exceptions, this
library being ported to a certain platform should mean that most officials
libraries can run on that platform.

Asynchronous I/O was popularized primarily via libuv, which is the C library on
top of which the now ubiquitous Node.js JavaScript runtime is built. That
library, as well as the alternatives we know of, such as libevent and libev,
were designed primarily to support creating server applications for the World
Wide Web. As such, they make rather strong assumptions about the facilities of
the operating systems required to run them (such as the availability of
filesystems and inter-process signaling), as well as the hardware capabilities
of those servers. In contrast, this base library, and most of its official
companion libraries, are designed primarily to support creating machine-centric
applications, or system-of-systems. Many of those machines may have limited
software and hardware capabilities, such as not being able to run full operating
systems or not having access to significant compute or memory facilities. While
a WWW server will typically have at least hundreds of megabytes of RAM and disk
storage, an Arrowhead system running this library may have a few hundred of
kilobytes of RAM and ROM.

*/