// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ERR_H_
#define AH_ERR_H_

#include "defs.h"

#if AH_IS_WIN32
#    include <winerror.h>
#else
#    include <errno.h>
#endif

#if AH_IS_WIN32
#    define AH_I_ERR_MAP_EXTRAS

#else
#    define AH_I_ERR_MAP_EXTRAS                                                                                        \
        E(2BIG, E2BIG, 6000, "argument list too long")                                                                 \
        E(AGAIN, EAGAIN, 6005, "try again")                                                                            \
        E(BADMSG, EBADMSG, 6008, "bad message")                                                                        \
        E(BUSY, EBUSY, WSAEBUSY, "busy")                                                                               \
        E(CANCELED, ECANCELED, WSAECANCELED, "canceled")                                                               \
        E(CHILD, ECHILD, WSAECHILD, "no child processes")                                                              \
        E(DEADLK, EDEADLK, WSAEDEADLK, "deadlock would occur")                                                         \
        E(DOM, EDOM, WSAEDOM, "arithmetic argument outside accepted domain")                                           \
        E(EXIST, EEXIST, WSAEEXIST, "already exists")                                                                  \
        E(FBIG, EFBIG, WSAEFBIG, "file too large")                                                                     \
        E(IDRM, EIDRM, WSAEIDRM, "identifier removed")                                                                 \
        E(ILSEQ, EILSEQ, WSAEILSEQ, "illegal byte sequence")                                                           \
        E(IO, EIO, WSAEIO, "I/O error")                                                                                \
        E(ISDIR, EISDIR, WSAEISDIR, "is directory")                                                                    \
        E(MLINK, EMLINK, WSAEMLINK, "too many links")                                                                  \
        E(NFILE, ENFILE, WSAENFILE, "platform file table full")                                                        \
        E(NODATA, ENODATA, WSAENODATA, "no data available")                                                            \
        E(NODEV, ENODEV, WSAENODEV, "no such device")                                                                  \
        E(NOENT, ENOENT, WSAENOENT, "no such entry")                                                                   \
        E(NOEXEC, ENOEXEC, WSAENOEXEC, "not a valid executable")                                                       \
        E(NOLCK, ENOLCK, WSAENOLCK, "no locks available")                                                              \
        E(NOMSG, ENOMSG, WSAENOMSG, "no message of the desired type")                           \

#endif

#define AH_I_ERR_MAP(E)                                                                                                \
    E(EOF, 5000, 5000, "unexpected end of stream")                                                                     \
    E(STATE, 5001, 5001, "state invalid")                                                                              \
                                                                                                                       \
    E(ACCES, EACCES, WSAEACCES, "permission denied")                                                                   \
    E(ADDRINUSE, EADDRINUSE, WSAEADDRINUSE, "address in use")                                                          \
    E(ADDRNOTAVAIL, EADDRNOTAVAIL, WSAEADDRNOTAVAIL, "address not available")                                          \
    E(AFNOSUPPORT, EAFNOSUPPORT, WSAEAFNOSUPPORT, "address family not supported")                                      \
    E(ALREADY, EALREADY, WSAEALREADY, "already in progress")                                                           \
    E(BADF, EBADF, WSAEBADF, "bad file descriptor")                                                                    \
    E(CONNABORTED, ECONNABORTED, WSAECONNABORTED, "connection aborted")                                                \
    E(CONNREFUSED, ECONNREFUSED, WSAECONNREFUSED, "connection refused")                                                \
    E(CONNRESET, ECONNRESET, WSAECONNRESET, "connection reset")                                                        \
    E(DESTADDRREQ, EDESTADDRREQ, WSAEDESTADDRREQ, "destination address required")                                      \
    E(FAULT, EFAULT, WSAEFAULT, "bad address")                                                                         \
    E(HOSTUNREACH, EHOSTUNREACH, WSAEHOSTUNREACH, "host unreachable")                                                  \
    E(INPROGRESS, EINPROGRESS, WSAEINPROGRESS, "already in progress")                                                  \
    E(INTR, EINTR, WSAEINTR, "interrupted")                                                                            \
    E(INVAL, EINVAL, WSAEINVAL, "invalid argument")                                                                    \
    E(ISCONN, EISCONN, WSAEISCONN, "is connected")                                                                     \
    E(LOOP, ELOOP, WSAELOOP, "symbolic links loop")                                                                    \
    E(MFILE, EMFILE, WSAEMFILE, "process file table full")                                                             \
    E(MSGSIZE, EMSGSIZE, WSAEMSGSIZE, "message too large")                                                             \
    E(NAMETOOLONG, ENAMETOOLONG, WSAENAMETOOLONG, "filename too long")                                                 \
    E(NETDOWN, ENETDOWN, WSAENETDOWN, "network down")                                                                  \
    E(NETRESET, ENETRESET, WSAENETRESET, "connection reset by network")                                                \
    E(NETUNREACH, ENETUNREACH, WSAENETUNREACH, "network unreachable")                                                  \
    E(NOBUFS, ENOBUFS, WSAENOBUFS, "no buffer space available")                                                        \
    E(NOMEM, ENOMEM, WSA_NOT_ENOUGH_MEMORY, "not enough memory")                                                       \
    E(NOPROTOOPT, ENOPROTOOPT, WSAENOPROTOOPT, "protocol not available")                                               \
    E(NOSPC, ENOSPC, WSAENOSPC, "not enough space")                                                                    \
    E(NOTCONN, ENOTCONN, WSAENOTCONN, "not connected")                                                                 \
    E(NOTDIR, ENOTDIR, WSAENOTDIR, "not a directory")                                                                  \
    E(NOTEMPTY, ENOTEMPTY, WSAENOTEMPTY, "not empty")                                                                  \
    E(NOTSOCK, ENOTSOCK, WSAENOTSOCK, "not a socket")                                                                  \
    E(NOTSUP, ENOTSUP, WSAENOTSUP, "not supported")                                                                    \
    E(NXIO, ENXIO, WSAENXIO, "no such device or address")                                                              \
    E(OVERFLOW, EOVERFLOW, WSAEOVERFLOW, "value too large to fit in target")                                           \
    E(PERM, EPERM, WSAEPERM, "not permitted")                                                                          \
    E(PROTO, EPROTO, WSAEPROTO, "protocol error")                                                                      \
    E(PROTONOSUPPORT, EPROTONOSUPPORT, WSAEPROTONOSUPPORT, "protocol not supported")                                   \
    E(PROTOTYPE, EPROTOTYPE, WSAEPROTOTYPE, "wrong protocol type")                                                     \
    E(RANGE, ERANGE, WSAERANGE, "arithmetic result outside accepted range")                                            \
    E(ROFS, EROFS, WSAEROFS, "read-only file system")                                                                  \
    E(SPIPE, ESPIPE, WSAESPIPE, "invalid seek")                                                                        \
    E(SRCH, ESRCH, WSAESRCH, "not found")                                                                              \
    E(TIME, ETIME, WSAETIME, "expired")                                                                                \
    E(TIMEDOUT, ETIMEDOUT, WSAETIMEDOUT, "timed out")                                                                  \
    E(TXTBSY, ETXTBSY, WSAETXTBSY, "text file busy")                                                                   \
    E(XDEV, EXDEV, WSAEXDEV, "cross-device link")

// WSA_INVALID_HANDLE
// WSA_NOT_ENOUGH_MEMORY
// WSA_INVALID_PARAMETER
// WSA_OPERATION_ABORTED
// WSA_IO_INCOMPLETE
// WSA_IO_PENDING
// WSAEINTR
// WSAEBADF
// WSAEACCES
// WSAEFAULT
// WSAEINVAL
// WSAEMFILE
// WSAEWOULDBLOCK
// WSAEINPROGRESS
// WSAEALREADY
// WSAENOTSOCK
// WSAEDESTADDRREQ
// WSAEMSGSIZE
// WSAEPROTOTYPE
// WSAENOPROTOOPT
// WSAEPROTONOSUPPORT
// WSAESOCKTNOSUPPORT
// WSAEOPNOTSUPP
// WSAEPFNOSUPPORT
// WSAEAFNOSUPPORT
// WSAEADDRINUSE
// WSAEADDRNOTAVAIL
// WSAENETDOWN
// WSAENETUNREACH
// WSAENETRESET
// WSAECONNABORTED
// WSAECONNRESET
// WSAENOBUFS
// WSAEISCONN
// WSAENOTCONN
// WSAESHUTDOWN
// WSAETOOMANYREFS
// WSAETIMEDOUT
// WSAECONNREFUSED
// WSAELOOP
// WSAENAMETOOLONG
// WSAEHOSTDOWN
// WSAEHOSTUNREACH
// WSAENOTEMPTY
// WSAEPROCLIM
// WSAEUSERS
// WSAEDQUOT
// WSAESTALE
// WSAEREMOTE
// WSASYSNOTREADY
// WSAVERNOTSUPPORTED
// WSANOTINITIALISED
// WSAEDISCON
// WSAENOMORE
// WSAECANCELLED
// WSAEINVALIDPROCTABLE
// WSAEINVALIDPROVIDER
// WSAEPROVIDERFAILEDINIT
// WSASYSCALLFAILURE
// WSASERVICE_NOT_FOUND
// WSATYPE_NOT_FOUND
// WSA_E_NO_MORE
// WSA_E_CANCELLED
// WSAEREFUSED
// WSAHOST_NOT_FOUND
// WSATRY_AGAIN
// WSANO_RECOVERY
// WSANO_DATA


enum {
    AH_ENONE = 0,

#if AH_USE_POSIX
#    define AH_I_ERR_E(NAME, POSIX_CODE, WIN32_CODE, STRING) AH_E##NAME = (POSIX_CODE),
#elif AH_USE_WIN32
#    define AH_I_ERR_E(NAME, POSIX_CODE, WIN32_CODE, STRING) AH_E##NAME = (WIN32_CODE),
#endif

    AH_I_ERR_MAP(AH_I_ERR_E)

#undef AH_I_ERR_E

};

ah_extern const char* ah_strerror(ah_err_t err);

#endif
