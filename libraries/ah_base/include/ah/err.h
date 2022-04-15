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

#if AH_IS_DARWIN
#    define AH_I_ERR_MAP_PLATFORM(P)                                                                                   \
        P(BADARCH, EBADARCH "bad CPU type in executable")                                                              \
        P(BADEXEC, EBADEXEC "bad executable")                                                                          \
        P(BADMACHO, EBADMACHO "malformed Macho file")                                                                  \
        P(FTYPE, EFTYPE "inappropriate file type or format")                                                           \
        P(NEEDAUTH, ENEEDAUTH "need authenticator")                                                                    \
        P(PROCLIM, EPROCLIM "process limit reached")                                                                   \
        P(PROCUNAVAIL, EPROCUNAVAIL "bad procedure for program")                                                       \
        P(PROGMISMATCH, EPROGMISMATCH "program version wrong")                                                         \
        P(SHLIBVERS, ESHLIBVERS "shared library version mismatch")

#elif AH_IS_LINUX
#    define AH_I_ERR_MAP_PLATFORM(P)                                                                                   \
        P(LIBACC, ELIBACC, "needed shared library inaccessible")                                                       \
        P(LIBBAD, ELIBBAD, "shared library corrupted")                                                                 \
        P(LIBEXEC, ELIBEXEC, "cannot execute shared library")                                                          \
        P(LIBMAX, ELIBMAX, "attempting to link in too many shared libraries")                                          \
        P(LIBSCN, ELIBSCN, ".lib section in a.out corrupted")                                                          \
        P(NONET, ENONET, "not on the network")                                                                         \
        P(NOTUNIQ, ENOTUNIQ, "name not unique on network")                                                             \
        P(REMCHG, EREMCHG, "remote address changed")                                                                   \
        P(STRPIPE, ESTRPIPE, "streams pipe error")

#elif AH_IS_WIN32
#    define AH_I_ERR_MAP_PLATFORM(P)                                                                                   \
        P(DISCON, WSAEDISCON, "disconneted")                                                                           \
        P(HOSTNOTFOUND, WSAHOST_NOT_FOUND, "host not found")                                                           \
        P(PROCLIM, WSAEPROCLIM, "execution process limit reached")                                                     \
        P(SECHOSTNOTFOUND, WSA_SECURE_HOST_NOT_FOUND, "secure host not found")                                         \
        P(SYSNOTREADY, WSASYSNOTREADY, "networking system not ready")

#endif

#define AH_I_ERR_MAP(E, P)                                                                                             \
    E(EOF, 5401, 5401, "unexpected end of stream")                                                                     \
    E(STATE, 5402, 5402, "state invalid")                                                                              \
                                                                                                                       \
    E(2BIG, E2BIG, 5501, "argument list too long")                                                                     \
    E(ACCES, EACCES, WSAEACCES, "permission denied")                                                                   \
    E(ADDRINUSE, EADDRINUSE, WSAEADDRINUSE, "address in use")                                                          \
    E(ADDRNOTAVAIL, EADDRNOTAVAIL, WSAEADDRNOTAVAIL, "address not available")                                          \
    E(AFNOSUPPORT, EAFNOSUPPORT, WSAEAFNOSUPPORT, "address family not supported")                                      \
    E(AGAIN, EAGAIN, WSAEWOULDBLOCK, "try again")                                                                      \
    E(ALREADY, EALREADY, WSAEALREADY, "already in progress")                                                           \
    E(BADF, EBADF, WSAEBADF, "bad file descriptor")                                                                    \
    E(BADMSG, EBADMSG, 5502, "bad message")                                                                            \
    E(BUSY, EBUSY, 5503, "device or resource busy")                                                                    \
    E(CANCELED, ECANCELED, WSAECANCELLED, "operation canceled")                                                        \
    E(CHILD, ECHILD, 5504, "no child processes")                                                                       \
    E(CONNABORTED, ECONNABORTED, WSAECONNABORTED, "connection aborted")                                                \
    E(CONNREFUSED, ECONNREFUSED, WSAECONNREFUSED, "connection refused")                                                \
    E(CONNRESET, ECONNRESET, WSAECONNRESET, "connection reset")                                                        \
    E(DEADLK, EDEADLK, 5505, "resource deadlock would occur")                                                          \
    E(DESTADDRREQ, EDESTADDRREQ, WSAEDESTADDRREQ, "destination address required")                                      \
    E(DOM, EDOM, 5506, "arithmetic argument outside accepted domain")                                                  \
    E(DQUOT, EDQUOT, WSAEDQUOT, "disc quota exceeded")                                                                 \
    E(EXIST, EEXIST, 5507, "file exists")                                                                              \
    E(FAULT, EFAULT, WSAEFAULT, "bad address")                                                                         \
    E(FBIG, EFBIG, 5508, "file too large")                                                                             \
    E(HOSTDOWN, EHOSTDOWN, WSAEHOSTDOWN, "host down")                                                                  \
    E(HOSTUNREACH, EHOSTUNREACH, WSAEHOSTUNREACH, "host unreachable")                                                  \
    E(IDRM, EIDRM, 5509, "identifier removed")                                                                         \
    E(ILSEQ, EILSEQ, 5510, "illegal byte sequence")                                                                    \
    E(INPROGRESS, EINPROGRESS, WSAEINPROGRESS, "operation in progress")                                                \
    E(INTR, EINTR, WSAEINTR, "interrupted function")                                                                   \
    E(INVAL, EINVAL, WSAEINVAL, "invalid argument")                                                                    \
    E(IO, EIO, 5511, "I/O error")                                                                                      \
    E(ISCONN, EISCONN, WSAEISCONN, "already connected")                                                                \
    E(ISDIR, EISDIR, 5512, "is a directory")                                                                           \
    E(LOOP, ELOOP, WSAELOOP, "too many levels of symbolic links")                                                      \
    E(MFILE, EMFILE, WSAEMFILE, "file descriptor value too large")                                                     \
    E(MLINK, EMLINK, 5513, "too many links")                                                                           \
    E(MSGSIZE, EMSGSIZE, WSAEMSGSIZE, "message too large")                                                             \
    E(MULTIHOP, EMULTIHOP, 5514, "incomplete route path")                                                              \
    E(NAMETOOLONG, ENAMETOOLONG, WSAENAMETOOLONG, "filename too long")                                                 \
    E(NETDOWN, ENETDOWN, WSAENETDOWN, "network is down")                                                               \
    E(NETRESET, ENETRESET, WSAENETRESET, "connection aborted by network")                                              \
    E(NETUNREACH, ENETUNREACH, WSAENETUNREACH, "network unreachable")                                                  \
    E(NFILE, ENFILE, 5515, "too many files open in system")                                                            \
    E(NOBUFS, ENOBUFS, WSAENOBUFS, "no buffer space available")                                                        \
    E(NODATA, ENODATA, 5516, "no data available")                                                                      \
    E(NODEV, ENODEV, 5517, "no such device")                                                                           \
    E(NOENT, ENOENT, 5518, "no such file or directory")                                                                \
    E(NOEXEC, ENOEXEC, 5519, "executable file format error")                                                           \
    E(NOLCK, ENOLCK, 5520, "no locks available")                                                                       \
    E(NOLINK, ENOLINK, 5521, "link severed")                                                                           \
    E(NOMEM, ENOMEM, ERROR_NOT_ENOUGH_MEMORY, "not enough memory")                                                       \
    E(NOMSG, ENOMSG, 5522, "no message of the desired type")                                                           \
    E(NOPROTOOPT, ENOPROTOOPT, WSAENOPROTOOPT, "protocol not available")                                               \
    E(NOSPC, ENOSPC, 5523, "no space left on device")                                                                  \
    E(NOSR, ENOSR, 5524, "no STREAM resources")                                                                        \
    E(NOSTR, ENOSTR, 5525, "not a STREAM")                                                                             \
    E(NOSYS, ENOSYS, WSASYSCALLFAILURE, "system call unsupported")                                                     \
    E(NOTBLK, ENOTBLK, 5526, "not a block device")                                                                     \
    E(NOTCONN, ENOTCONN, WSAENOTCONN, "not connected")                                                                 \
    E(NOTDIR, ENOTDIR, 5527, "not a directory or a symbolic link to a directory")                                      \
    E(NOTEMPTY, ENOTEMPTY, 5528, "not empty")                                                                          \
    E(NOTRECOVERABLE, ENOTRECOVERABLE, 5529, "not recoverable")                                                        \
    E(NOTSOCK, ENOTSOCK, WSAENOTSOCK, "not a socket")                                                                  \
    E(NXIO, ENXIO, 5530, "no such device or address")                                                                  \
    E(OPNOTSUPP, EOPNOTSUPP, WSAEOPNOTSUPP, "operation not supported")                                                 \
    E(OVERFLOW, EOVERFLOW, 5531, "value does not fit in target")                                                       \
    E(OWNERDEAD, EOWNERDEAD, 5532, "previous owner died")                                                              \
    E(PERM, EPERM, 5533, "not permitted")                                                                              \
    E(PFNOSUPPORT, EPFNOSUPPORT, WSAEPFNOSUPPORT, "protocol family not supported")                                     \
    E(PIPE, EPIPE, 5534, "broken pipe")                                                                                \
    E(PROTO, EPROTO, 5535, "protocol error")                                                                           \
    E(PROTONOSUPPORT, EPROTONOSUPPORT, WSAEPROTONOSUPPORT, "protocol not supported")                                   \
    E(PROTOTYPE, EPROTOTYPE, WSAEPROTOTYPE, "protocol type wrong")                                                     \
    E(RANGE, ERANGE, 5536, "arithmetic result outside accepted range")                                                 \
    E(ROFS, EROFS, 5537, "read-only file system")                                                                      \
    E(SHUTDOWN, ESHUTDOWN, WSAESHUTDOWN, "has shut down")                                                              \
    E(SOCKTNOSUPPORT, ESOCKTNOSUPPORT, WSAESOCKTNOSUPPORT, "socket type not supported")                                \
    E(SPIPE, ESPIPE, 5538, "broken pipe")                                                                              \
    E(SRCH, ESRCH, 5539, "no such process")                                                                            \
    E(STALE, ESTALE, WSAESTALE, "stale")                                                                               \
    E(TIME, ETIME, 5540, "timeout")                                                                                    \
    E(TIMEDOUT, ETIMEDOUT, WSAETIMEDOUT, "timed out")                                                                  \
    E(TOOMANYREFS, ETOOMANYREFS, WSAETOOMANYREFS, "too many references")                                               \
    E(TXTBSY, ETXTBSY, 5541, "text file busy")                                                                         \
    E(USERS, EUSERS, WSAEUSERS, "too many users")                                                                      \
    E(XDEV, EXDEV, 5542, "cross-device link")                                                                          \
    AH_I_ERR_MAP_PLATFORM(P)

enum {
    AH_ENONE = 0,

#if AH_IS_WIN32
#    define AH_I_ERR_E(NAME, POSIX_CODE, WIN32_CODE, STRING) AH_E##NAME = (WIN32_CODE),
#else
#    define AH_I_ERR_E(NAME, POSIX_CODE, WIN32_CODE, STRING) AH_E##NAME = (POSIX_CODE),
#endif

#define AH_I_ERR_P(NAME, CODE, STRING) AH_E##NAME = (CODE),

    AH_I_ERR_MAP(AH_I_ERR_E, AH_I_ERR_P)

#undef AH_I_ERR_P
#undef AH_I_ERR_E

};

ah_extern const char* ah_strerror(ah_err_t err);

#endif
