// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ERR_H_
#define AH_ERR_H_

#include "defs.h"

#if AH_IS_WIN32
# include <winerror.h>
#else
# include <errno.h>
#endif

#if AH_IS_WIN32
# define AH_I_ERR_ONE_OF(POSIX_CODE, WIN32_CODE) WIN32_CODE
#else
# define AH_I_ERR_ONE_OF(POSIX_CODE, WIN32_CODE) POSIX_CODE
#endif

#if AH_IS_DARWIN
# define AH_I_ERR_MAP_PLATFORM(E)                           \
  E(BADARCH, EBADARCH, "bad CPU type in executable")        \
  E(BADEXEC, EBADEXEC, "bad executable")                    \
  E(BADMACHO, EBADMACHO, "malformed Macho file")            \
  E(FTYPE, EFTYPE, "inappropriate file type or format")     \
  E(NEEDAUTH, ENEEDAUTH, "need authenticator")              \
  E(PROCLIM, EPROCLIM, "process limit reached")             \
  E(PROCUNAVAIL, EPROCUNAVAIL, "bad procedure for program") \
  E(PROGMISMATCH, EPROGMISMATCH, "program version wrong")   \
  E(SHLIBVERS, ESHLIBVERS, "shared library version mismatch")

#elif AH_IS_LINUX
# define AH_I_ERR_MAP_PLATFORM(E)                                       \
  E(LIBACC, ELIBACC, "needed shared library inaccessible")              \
  E(LIBBAD, ELIBBAD, "shared library corrupted")                        \
  E(LIBEXEC, ELIBEXEC, "cannot execute shared library")                 \
  E(LIBMAX, ELIBMAX, "attempting to link in too many shared libraries") \
  E(LIBSCN, ELIBSCN, ".lib section in a.out corrupted")                 \
  E(NONET, ENONET, "not on the network")                                \
  E(NOTUNIQ, ENOTUNIQ, "name not unique on network")                    \
  E(REMCHG, EREMCHG, "remote address changed")                          \
  E(STRPIPE, ESTRPIPE, "streams pipe error")

#elif AH_IS_WIN32
# define AH_I_ERR_MAP_PLATFORM(E)                                        \
  E(DISCON, WSAEDISCON, "disconneted")                                   \
  E(HOSTNOTFOUND, WSAHOST_NOT_FOUND, "host not found")                   \
  E(PROCLIM, WSAEPROCLIM, "execution process limit reached")             \
  E(SECHOSTNOTFOUND, WSA_SECURE_HOST_NOT_FOUND, "secure host not found") \
  E(SYSNOTREADY, WSASYSNOTREADY, "networking system not ready")

#endif

#define AH_I_ERR_MAP(E)                                                                               \
 E(DEP, 5405, "dependency error")                                                                     \
 E(DUP, 5403, "duplicate exists")                                                                     \
 E(EOF, 5401, "unexpected end of stream")                                                             \
 E(INTERN, 5404, "internal error")                                                                    \
 E(STATE, 5402, "state invalid")                                                                      \
                                                                                                      \
 E(2BIG, AH_I_ERR_ONE_OF(E2BIG, 5501), "argument list too long")                                      \
 E(ACCES, AH_I_ERR_ONE_OF(EACCES, WSAEACCES), "permission denied")                                    \
 E(ADDRINUSE, AH_I_ERR_ONE_OF(EADDRINUSE, WSAEADDRINUSE), "address in use")                           \
 E(ADDRNOTAVAIL, AH_I_ERR_ONE_OF(EADDRNOTAVAIL, WSAEADDRNOTAVAIL), "address not available")           \
 E(AFNOSUPPORT, AH_I_ERR_ONE_OF(EAFNOSUPPORT, WSAEAFNOSUPPORT), "address family not supported")       \
 E(AGAIN, AH_I_ERR_ONE_OF(EAGAIN, WSAEWOULDBLOCK), "try again")                                       \
 E(ALREADY, AH_I_ERR_ONE_OF(EALREADY, WSAEALREADY), "already in progress")                            \
 E(BADF, AH_I_ERR_ONE_OF(EBADF, WSAEBADF), "bad file descriptor")                                     \
 E(BADMSG, AH_I_ERR_ONE_OF(EBADMSG, 5502), "bad message")                                             \
 E(BUSY, AH_I_ERR_ONE_OF(EBUSY, 5503), "device or resource busy")                                     \
 E(CANCELED, AH_I_ERR_ONE_OF(ECANCELED, WSAECANCELLED), "operation canceled")                         \
 E(CHILD, AH_I_ERR_ONE_OF(ECHILD, 5504), "no child processes")                                        \
 E(CONNABORTED, AH_I_ERR_ONE_OF(ECONNABORTED, WSAECONNABORTED), "connection aborted")                 \
 E(CONNREFUSED, AH_I_ERR_ONE_OF(ECONNREFUSED, WSAECONNREFUSED), "connection refused")                 \
 E(CONNRESET, AH_I_ERR_ONE_OF(ECONNRESET, WSAECONNRESET), "connection reset")                         \
 E(DEADLK, AH_I_ERR_ONE_OF(EDEADLK, 5505), "deadlock would occur")                                    \
 E(DESTADDRREQ, AH_I_ERR_ONE_OF(EDESTADDRREQ, WSAEDESTADDRREQ), "destination address required")       \
 E(DOM, AH_I_ERR_ONE_OF(EDOM, 5506), "arithmetic argument outside accepted domain")                   \
 E(DQUOT, AH_I_ERR_ONE_OF(EDQUOT, WSAEDQUOT), "disc quota exceeded")                                  \
 E(EXIST, AH_I_ERR_ONE_OF(EEXIST, 5507), "already exists")                                            \
 E(FAULT, AH_I_ERR_ONE_OF(EFAULT, WSAEFAULT), "bad address")                                          \
 E(FBIG, AH_I_ERR_ONE_OF(EFBIG, 5508), "file too large")                                              \
 E(HOSTDOWN, AH_I_ERR_ONE_OF(EHOSTDOWN, WSAEHOSTDOWN), "host down")                                   \
 E(HOSTUNREACH, AH_I_ERR_ONE_OF(EHOSTUNREACH, WSAEHOSTUNREACH), "host unreachable")                   \
 E(IDRM, AH_I_ERR_ONE_OF(EIDRM, 5509), "identifier removed")                                          \
 E(ILSEQ, AH_I_ERR_ONE_OF(EILSEQ, 5510), "illegal byte sequence")                                     \
 E(INPROGRESS, AH_I_ERR_ONE_OF(EINPROGRESS, WSAEINPROGRESS), "operation in progress")                 \
 E(INTR, AH_I_ERR_ONE_OF(EINTR, WSAEINTR), "interrupted")                                             \
 E(INVAL, AH_I_ERR_ONE_OF(EINVAL, WSAEINVAL), "invalid argument")                                     \
 E(IO, AH_I_ERR_ONE_OF(EIO, 5511), "I/O error")                                                       \
 E(ISCONN, AH_I_ERR_ONE_OF(EISCONN, WSAEISCONN), "already connected")                                 \
 E(ISDIR, AH_I_ERR_ONE_OF(EISDIR, 5512), "is a directory")                                            \
 E(LOOP, AH_I_ERR_ONE_OF(ELOOP, WSAELOOP), "too many levels of symbolic links")                       \
 E(MFILE, AH_I_ERR_ONE_OF(EMFILE, WSAEMFILE), "file descriptor value too large")                      \
 E(MLINK, AH_I_ERR_ONE_OF(EMLINK, 5513), "too many links")                                            \
 E(MSGSIZE, AH_I_ERR_ONE_OF(EMSGSIZE, WSAEMSGSIZE), "message too large")                              \
 E(MULTIHOP, AH_I_ERR_ONE_OF(EMULTIHOP, 5514), "incomplete route path")                               \
 E(NAMETOOLONG, AH_I_ERR_ONE_OF(ENAMETOOLONG, WSAENAMETOOLONG), "name too long")                      \
 E(NETDOWN, AH_I_ERR_ONE_OF(ENETDOWN, WSAENETDOWN), "network is down")                                \
 E(NETRESET, AH_I_ERR_ONE_OF(ENETRESET, WSAENETRESET), "connection aborted by network")               \
 E(NETUNREACH, AH_I_ERR_ONE_OF(ENETUNREACH, WSAENETUNREACH), "network unreachable")                   \
 E(NFILE, AH_I_ERR_ONE_OF(ENFILE, 5515), "too many files open in system")                             \
 E(NOBUFS, AH_I_ERR_ONE_OF(ENOBUFS, WSAENOBUFS), "no buffer space available")                         \
 E(NODATA, AH_I_ERR_ONE_OF(ENODATA, 5516), "no data available")                                       \
 E(NODEV, AH_I_ERR_ONE_OF(ENODEV, 5517), "no such device")                                            \
 E(NOENT, AH_I_ERR_ONE_OF(ENOENT, 5518), "no such entry")                                             \
 E(NOEXEC, AH_I_ERR_ONE_OF(ENOEXEC, 5519), "executable file format error")                            \
 E(NOLCK, AH_I_ERR_ONE_OF(ENOLCK, 5520), "no locks available")                                        \
 E(NOLINK, AH_I_ERR_ONE_OF(ENOLINK, 5521), "link severed")                                            \
 E(NOMEM, AH_I_ERR_ONE_OF(ENOMEM, ERROR_NOT_ENOUGH_MEMORY), "not enough memory")                      \
 E(NOMSG, AH_I_ERR_ONE_OF(ENOMSG, 5522), "no such message")                                           \
 E(NOPROTOOPT, AH_I_ERR_ONE_OF(ENOPROTOOPT, WSAENOPROTOOPT), "protocol not available")                \
 E(NOSPC, AH_I_ERR_ONE_OF(ENOSPC, 5523), "no space left")                                             \
 E(NOSR, AH_I_ERR_ONE_OF(ENOSR, 5524), "no STREAM resources")                                         \
 E(NOSTR, AH_I_ERR_ONE_OF(ENOSTR, 5525), "not a STREAM")                                              \
 E(NOSYS, AH_I_ERR_ONE_OF(ENOSYS, WSASYSCALLFAILURE), "system call unsupported")                      \
 E(NOTBLK, AH_I_ERR_ONE_OF(ENOTBLK, 5526), "not a block device")                                      \
 E(NOTCONN, AH_I_ERR_ONE_OF(ENOTCONN, WSAENOTCONN), "not connected")                                  \
 E(NOTDIR, AH_I_ERR_ONE_OF(ENOTDIR, 5527), "not a directory or a symbolic link to a directory")       \
 E(NOTEMPTY, AH_I_ERR_ONE_OF(ENOTEMPTY, 5528), "not empty")                                           \
 E(NOTRECOVERABLE, AH_I_ERR_ONE_OF(ENOTRECOVERABLE, 5529), "not recoverable")                         \
 E(NOTSOCK, AH_I_ERR_ONE_OF(ENOTSOCK, WSAENOTSOCK), "not a socket")                                   \
 E(NXIO, AH_I_ERR_ONE_OF(ENXIO, 5530), "no such device or address")                                   \
 E(OPNOTSUPP, AH_I_ERR_ONE_OF(EOPNOTSUPP, WSAEOPNOTSUPP), "operation not supported")                  \
 E(OVERFLOW, AH_I_ERR_ONE_OF(EOVERFLOW, 5531), "value does not fit in target")                        \
 E(OWNERDEAD, AH_I_ERR_ONE_OF(EOWNERDEAD, 5532), "previous owner died")                               \
 E(PERM, AH_I_ERR_ONE_OF(EPERM, 5533), "not permitted")                                               \
 E(PFNOSUPPORT, AH_I_ERR_ONE_OF(EPFNOSUPPORT, WSAEPFNOSUPPORT), "protocol family not supported")      \
 E(PIPE, AH_I_ERR_ONE_OF(EPIPE, 5534), "broken pipe")                                                 \
 E(PROTO, AH_I_ERR_ONE_OF(EPROTO, 5535), "protocol error")                                            \
 E(PROTONOSUPPORT, AH_I_ERR_ONE_OF(EPROTONOSUPPORT, WSAEPROTONOSUPPORT), "protocol not supported")    \
 E(PROTOTYPE, AH_I_ERR_ONE_OF(EPROTOTYPE, WSAEPROTOTYPE), "protocol type wrong")                      \
 E(RANGE, AH_I_ERR_ONE_OF(ERANGE, 5536), "arithmetic result outside accepted range")                  \
 E(ROFS, AH_I_ERR_ONE_OF(EROFS, 5537), "read-only file system")                                       \
 E(SHUTDOWN, AH_I_ERR_ONE_OF(ESHUTDOWN, WSAESHUTDOWN), "has shut down")                               \
 E(SOCKTNOSUPPORT, AH_I_ERR_ONE_OF(ESOCKTNOSUPPORT, WSAESOCKTNOSUPPORT), "socket type not supported") \
 E(SPIPE, AH_I_ERR_ONE_OF(ESPIPE, 5538), "broken pipe")                                               \
 E(SRCH, AH_I_ERR_ONE_OF(ESRCH, 5539), "not found")                                                   \
 E(STALE, AH_I_ERR_ONE_OF(ESTALE, WSAESTALE), "stale")                                                \
 E(TIME, AH_I_ERR_ONE_OF(ETIME, 5540), "timeout")                                                     \
 E(TIMEDOUT, AH_I_ERR_ONE_OF(ETIMEDOUT, WSAETIMEDOUT), "timed out")                                   \
 E(TOOMANYREFS, AH_I_ERR_ONE_OF(ETOOMANYREFS, WSAETOOMANYREFS), "too many references")                \
 E(TXTBSY, AH_I_ERR_ONE_OF(ETXTBSY, 5541), "text file busy")                                          \
 E(USERS, AH_I_ERR_ONE_OF(EUSERS, WSAEUSERS), "too many users")                                       \
 E(XDEV, AH_I_ERR_ONE_OF(EXDEV, 5542), "cross-device link")                                           \
 AH_I_ERR_MAP_PLATFORM(E)

enum {
    AH_ENONE = 0,

#define AH_I_ERR_E(NAME, CODE, STRING) AH_E##NAME = (CODE),
    AH_I_ERR_MAP(AH_I_ERR_E)
#undef AH_I_ERR_E
};

ah_extern const char* ah_strerror(ah_err_t err);

#endif
