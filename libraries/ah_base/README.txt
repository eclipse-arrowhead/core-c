/** @dir

Arrowhead Core C base library.

This library provides the foundation upon which most other Core C libraries
depend. It most significantly exposes a cross-platform API over some I/O
utilities provided by the targeted platforms, such as TCP/IP networking. Most of
the I/O operations exposed by this library are provided as asynchronous
functions, which is to say that their results are provided after they return by
invoking given callback functions. All asynchronous functionality of the library
is managed via <i>event loops</i> (see include/ah/loop.h), which can be seen as
single-threaded event queues managed by this library.

As managing events require several kinds of peripheral functionality, some of
that is also exposed, or made configurable (see include/ah/conf.h), by this
library. Buffers, error codes, safe math functions and time querying are some
notable examples.

Another primary purpose of this library is to gather together all functionality
that must be ported in order for this and all other official Arrowhead Core C
libraries to support another platform. In other words, no other library in this
repository may directly depend on a platform-specific API.

*/