// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ERR_H_
#define AH_ERR_H_

#include "defs.h"

#include <errno.h>

#if AH_IS_WIN32
#    include <Winsock2.h>
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
    E(EOF, 5000, 5000, "unexpected end of stream")                                                                     \
    E(STATE, 5001, 5001, "state invalid")                                                                              \
                                                                                                                       \
    E(2BIG, E2BIG, -E2BIG, "argument list too long")                                                                   \
    E(ACCES, EACCES, WSAEACCES, "permission denied")                                                                   \
    E(ADDRINUSE, EADDRINUSE, WSAEADDRINUSE, "address in use")                                                          \
    E(ADDRNOTAVAIL, EADDRNOTAVAIL, WSAEADDRNOTAVAIL, "address not available")                                          \
    E(AFNOSUPPORT, EAFNOSUPPORT, WSAEAFNOSUPPORT, "address family not supported")                                      \
    E(AGAIN, EAGAIN, -EAGAIN, "connection already in progress")                                                        \
    E(ALREADY, EALREADY, WSAEALREADY, "connection already in progress")                                                \
    E(BADF, EBADF, WSAEBADF, "bad file descriptor")                                                                    \
    E(BADMSG, EBADMSG, -EBADMSG, "bad message")                                                                        \
    E(BUSY, EBUSY, -EBUSY, "device or resource busy")                                                                  \
    E(CANCELED, ECANCELED, WSAECANCELLED, "operation canceled")                                                        \
    E(CHILD, ECHILD, -ECHILD, "no child processes")                                                                    \
    E(CONNABORTED, ECONNABORTED, WSAECONNABORTED, "connection aborted")                                                \
    E(CONNREFUSED, ECONNREFUSED, WSAECONNREFUSED, "connection refused")                                                \
    E(CONNRESET, ECONNRESET, WSAECONNRESET, "connection reset")                                                        \
    E(DEADLK, EDEADLK, -EDEADLK, "resource deadlock would occur")                                                      \
    E(DESTADDRREQ, EDESTADDRREQ, WSAEDESTADDRREQ, "destination address required")                                      \
    E(DOM, EDOM, -EDOM, "arithmetic argument outside accepted domain")                                                 \
    E(DQUOT, EDQUOT, WSAEDQUOT, "disc quota exceeded")                                                                 \
    E(EXIST, EEXIST, -EEXIST, "file exists")                                                                           \
    E(FAULT, EFAULT, WSAEFAULT, "bad address")                                                                         \
    E(FBIG, EFBIG, -EFBIG, "file too large")                                                                           \
    E(HOSTDOWN, EHOSTDOWN, WSAEHOSTDOWN, "host down")                                                                  \
    E(HOSTUNREACH, EHOSTUNREACH, WSAEHOSTUNREACH, "host unreachable")                                                  \
    E(IDRM, EIDRM, -EIDRM, "identifier removed")                                                                       \
    E(ILSEQ, EILSEQ, -EILSEQ, "illegal byte sequence")                                                                 \
    E(INPROGRESS, EINPROGRESS, WSAEINPROGRESS, "operation in progress")                                                \
    E(INTR, EINTR, WSAEINTR, "interrupted function")                                                                   \
    E(INVAL, EINVAL, WSAEINVAL, "invalid argument")                                                                    \
    E(IO, EIO, EIO, "I/O error")                                                                                       \
    E(ISCONN, EISCONN, WSAEISCONN, "already connected")                                                                \
    E(ISDIR, EISDIR, -EISDIR, "is a directory")                                                                        \
    E(LOOP, ELOOP, WSAELOOP, "too many levels of symbolic links")                                                      \
    E(MFILE, EMFILE, WSAEMFILE, "file descriptor value too large")                                                     \
    E(MLINK, EMLINK, -EMLINK, "too many links")                                                                        \
    E(MSGSIZE, EMSGSIZE, WSAEMSGSIZE, "message too large")                                                             \
    E(NAMETOOLONG, ENAMETOOLONG, WSAENAMETOOLONG, "filename too long")                                                 \
    E(NETDOWN, ENETDOWN, WSAENETDOWN, "network is down")                                                               \
    E(NETRESET, ENETRESET, WSAENETRESET, "connection aborted by network")                                              \
    E(NETUNREACH, ENETUNREACH, WSAENETUNREACH, "network unreachable")                                                  \
    E(NFILE, ENFILE, -ENFILE, "too many files open in system")                                                         \
    E(NOBUFS, ENOBUFS, WSAENOBUFS, "no buffer space available")                                                        \
    E(NODATA, ENODATA, -ENODATA, "no data available")                                                                  \
    E(NODEV, ENODEV, -ENODEV, "no such device")                                                                        \
    E(NOENT, ENOENT, -ENOENT, "no such file or directory")                                                             \
    E(NOEXEC, ENOEXEC, -ENOEXEC, "executable file format error")                                                       \
    E(NOLCK, ENOLCK, -ENOLCK, "no locks available")                                                                    \
    E(NOLINK, ENOLINK, -ENOLINK, "link severed")                                                                       \
    E(NOMEM, ENOMEM, WSA_NOT_ENOUGH_MEMORY, "not enough memory")                                                       \
    E(NOMSG, ENOMSG, -ENOMSG, "no message of the desired type")                                                        \
    E(NOPROTOOPT, ENOPROTOOPT, WSAENOPROTOOPT, "protocol not available")                                               \
    E(NOSPC, ENOSPC, -ENOSPC, "no space left on device")                                                               \
    E(NOSR, ENOSR, -ENOSR, "no STREAM resources")                                                                      \
    E(NOSTR, ENOSTR, -ENOSTR, "not a STREAM")                                                                          \
    E(NOSYS, ENOSYS, WSASYSCALLFAILURE, "system call unsupported")                                                     \
    E(NOTCONN, ENOTCONN, WSAENOTCONN, "not connected")                                                                 \
    E(NOTDIR, ENOTDIR, -ENOTDIR, "not a directory or a symbolic link to a directory")                                  \
    E(TOOMANYREFS, ETOOMANYREFS, WSAETOOMANYREFS, "too many references")                                               \
    E(TXTBSY, ETXTBSY, -ETXTBSY, "text file busy")                                                                     \
    E(WOULDBLOCK, EWOULDBLOCK, WSAEWOULDBLOCK, "operation would block")                                                \
    E(XDEV, EXDEV, -EXDEV, "cross-device link")                                                                        \
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

#undef AH_I_ERR_E

};

ah_extern const char* ah_strerror(ah_err_t err);

#endif
