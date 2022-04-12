// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ERR_H_
#define AH_ERR_H_

#include "defs.h"

#include <errno.h>

#define AH_I_ERR_MAP(E)                                                                                                \
    E(EOF, 5000, 5000, "unexpected end of stream")                                                                     \
    E(STATE, 5001, 5001, "state invalid")                                                                              \
                                                                                                                       \
    E(2BIG, E2BIG, 6000, "argument list too long")                                                                     \
    E(ACCES, EACCES, 6001, "permission denied")                                                                        \
    E(ADDRINUSE, EADDRINUSE, 6002, "address in use")                                                                   \
    E(ADDRNOTAVAIL, EADDRNOTAVAIL, 6003, "address not available")                                                      \
    E(AFNOSUPPORT, EAFNOSUPPORT, 6004, "address family not supported")                                                 \
    E(AGAIN, EAGAIN, 6005, "try again")                                                                                \
    E(ALREADY, EALREADY, 6006, "already in progress")                                                                  \
    E(BADF, EBADF, 6007, "bad file descriptor")                                                                        \
    E(BADMSG, EBADMSG, 6008, "bad message")                                                                            \
    E(BUSY, EBUSY, 6009, "busy")                                                                                       \
    E(CANCELED, ECANCELED, 6010, "canceled")                                                                           \
    E(CHILD, ECHILD, 6011, "no child processes")                                                                       \
    E(CONNABORTED, ECONNABORTED, 6012, "connection aborted")                                                           \
    E(CONNREFUSED, ECONNREFUSED, 6013, "connection refused")                                                           \
    E(CONNRESET, ECONNRESET, 6014, "connection reset")                                                                 \
    E(DEADLK, EDEADLK, 6015, "deadlock would occur")                                                                   \
    E(DESTADDRREQ, EDESTADDRREQ, 6016, "destination address required")                                                 \
    E(DOM, EDOM, 6017, "arithmetic argument outside accepted domain")                                                  \
    E(EXIST, EEXIST, 6018, "already exists")                                                                           \
    E(FAULT, EFAULT, 6019, "bad address")                                                                              \
    E(FBIG, EFBIG, 6020, "file too large")                                                                             \
    E(HOSTUNREACH, EHOSTUNREACH, 6021, "host unreachable")                                                             \
    E(IDRM, EIDRM, 6022, "identifier removed")                                                                         \
    E(ILSEQ, EILSEQ, 6023, "illegal byte sequence")                                                                    \
    E(INPROGRESS, EINPROGRESS, 6024, "already in progress")                                                            \
    E(INTR, EINTR, 6025, "interrupted")                                                                                \
    E(INVAL, EINVAL, 6026, "invalid argument")                                                                         \
    E(IO, EIO, 6027, "I/O error")                                                                                      \
    E(ISCONN, EISCONN, 6028, "is connected")                                                                           \
    E(ISDIR, EISDIR, 6029, "is directory")                                                                             \
    E(LOOP, ELOOP, 6030, "symbolic links loop")                                                                        \
    E(MFILE, EMFILE, 6031, "process file table full")                                                                  \
    E(MLINK, EMLINK, 6032, "too many links")                                                                           \
    E(MSGSIZE, EMSGSIZE, 6033, "message too large")                                                                    \
    E(NAMETOOLONG, ENAMETOOLONG, 6034, "filename too long")                                                            \
    E(NETDOWN, ENETDOWN, 6035, "network down")                                                                         \
    E(NETRESET, ENETRESET, 6036, "connection reset by network")                                                        \
    E(NETUNREACH, ENETUNREACH, 6037, "network unreachable")                                                            \
    E(NFILE, ENFILE, 6038, "platform file table full")                                                                 \
    E(NOBUFS, ENOBUFS, 6039, "no buffer space available")                                                              \
    E(NODATA, ENODATA, 6040, "no data available")                                                                      \
    E(NODEV, ENODEV, 6041, "no such device")                                                                           \
    E(NOENT, ENOENT, 6042, "no such entry")                                                                            \
    E(NOEXEC, ENOEXEC, 6043, "not a valid executable")                                                                 \
    E(NOLCK, ENOLCK, 6044, "no locks available")                                                                       \
    E(NOMEM, ENOMEM, 6045, "not enough memory")                                                                        \
    E(NOMSG, ENOMSG, 6046, "no message of the desired type")                                                           \
    E(NOPROTOOPT, ENOPROTOOPT, 6047, "protocol not available")                                                         \
    E(NOSPC, ENOSPC, 6048, "not enough space")                                                                         \
    E(NOTCONN, ENOTCONN, 6049, "not connected")                                                                        \
    E(NOTDIR, ENOTDIR, 6050, "not a directory")                                                                        \
    E(NOTEMPTY, ENOTEMPTY, 6051, "not empty")                                                                          \
    E(NOTSOCK, ENOTSOCK, 6052, "not a socket")                                                                         \
    E(NOTSUP, ENOTSUP, 6053, "not supported")                                                                          \
    E(NXIO, ENXIO, 6054, "no such device or address")                                                                  \
    E(OVERFLOW, EOVERFLOW, 6055, "value too large to fit in target")                                                   \
    E(PERM, EPERM, 6056, "not permitted")                                                                              \
    E(PROTO, EPROTO, 6057, "protocol error")                                                                           \
    E(PROTONOSUPPORT, EPROTONOSUPPORT, 6058, "protocol not supported")                                                 \
    E(PROTOTYPE, EPROTOTYPE, 6059, "wrong protocol type")                                                              \
    E(RANGE, ERANGE, 6060, "arithmetic result outside accepted range")                                                 \
    E(ROFS, EROFS, 6061, "read-only file system")                                                                      \
    E(SPIPE, ESPIPE, 6062, "invalid seek")                                                                             \
    E(SRCH, ESRCH, 6063, "not found")                                                                                  \
    E(TIME, ETIME, 6064, "expired")                                                                                    \
    E(TIMEDOUT, ETIMEDOUT, 6065, "timed out")                                                                          \
    E(TXTBSY, ETXTBSY, 6066, "text file busy")                                                                         \
    E(XDEV, EXDEV, 6067, "cross-device link")

enum {
    AH_ENONE = 0,

#if AH_USE_POSIX
#    define AH_I_ERR_E(NAME, POSIX_CODE, FALLBACK_CODE, STRING) AH_E##NAME = (POSIX_CODE),
#else
#    define AH_I_ERR_E(NAME, POSIX_CODE, FALLBACK_CODE, STRING) AH_E##NAME = (FALLBACK_CODE),
#endif

    AH_I_ERR_MAP(AH_I_ERR_E)

#undef AH_I_ERR_E

};

ah_extern const char* ah_strerror(ah_err_t err);

#endif
