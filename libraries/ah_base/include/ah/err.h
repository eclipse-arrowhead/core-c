// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ERR_H_
#define AH_ERR_H_

/**
 * @file
 * Error management
 *
 * This file lists most, if not all, error codes that can be returned by the
 * functions of the Core C library.
 */

#include "internal/_err.h"

/** No error. */
#define AH_ENONE 0

/**
 * @name Custom Errors
 * @{
 */
#define AH_EDEP    5405 /**< Consult dependency for error details. */
#define AH_EDUP    5403 /**< Duplicate exists. */
#define AH_EEOF    5401 /**< Unexpected end of resource. */
#define AH_EINTERN 5404 /**< Internal error. */
#define AH_ERECONN 5406 /**< Reconnection underway. */
#define AH_ESTATE  5402 /**< State invalid. */
#define AH_ESYNTAX 5407 /**< Syntax invalid. */
/** @} */

/**
 * @name POSIX Errors
 * @{
 */
#define AH_E2BIG           AH_I_ERR_ONE_OF(E2BIG, 5501)                         /**< Argument list too long. */
#define AH_EACCES          AH_I_ERR_ONE_OF(EACCES, WSAEACCES)                   /**< Permission denied. */
#define AH_EADDRINUSE      AH_I_ERR_ONE_OF(EADDRINUSE, WSAEADDRINUSE)           /**< Address in use. */
#define AH_EADDRNOTAVAIL   AH_I_ERR_ONE_OF(EADDRNOTAVAIL, WSAEADDRNOTAVAIL)     /**< Address not available. */
#define AH_EAFNOSUPPORT    AH_I_ERR_ONE_OF(EAFNOSUPPORT, WSAEAFNOSUPPORT)       /**< Address family not supported. */
#define AH_EAGAIN          AH_I_ERR_ONE_OF(EAGAIN, WSAEWOULDBLOCK)              /**< Try again. */
#define AH_EALREADY        AH_I_ERR_ONE_OF(EALREADY, WSAEALREADY)               /**< Already in progress. */
#define AH_EBADF           AH_I_ERR_ONE_OF(EBADF, WSAEBADF)                     /**< Bad file descriptor. */
#define AH_EBADMSG         AH_I_ERR_ONE_OF(EBADMSG, 5502)                       /**< Bad message. */
#define AH_EBUSY           AH_I_ERR_ONE_OF(EBUSY, 5503)                         /**< Device or resource busy. */
#define AH_ECANCELED       AH_I_ERR_ONE_OF(ECANCELED, WSAECANCELLED)            /**< Operation canceled. */
#define AH_ECHILD          AH_I_ERR_ONE_OF(ECHILD, 5504)                        /**< No child processes. */
#define AH_ECONNABORTED    AH_I_ERR_ONE_OF(ECONNABORTED, WSAECONNABORTED)       /**< Connection aborted. */
#define AH_ECONNREFUSED    AH_I_ERR_ONE_OF(ECONNREFUSED, WSAECONNREFUSED)       /**< Connection refused. */
#define AH_ECONNRESET      AH_I_ERR_ONE_OF(ECONNRESET, WSAECONNRESET)           /**< Connection reset. */
#define AH_EDEADLK         AH_I_ERR_ONE_OF(EDEADLK, 5505)                       /**< Deadlock would occur. */
#define AH_EDESTADDRREQ    AH_I_ERR_ONE_OF(EDESTADDRREQ, WSAEDESTADDRREQ)       /**< Destination address required. */
#define AH_EDOM            AH_I_ERR_ONE_OF(EDOM, 5506)                          /**< Arithmetic argument outside accepted domain. */
#define AH_EDQUOT          AH_I_ERR_ONE_OF(EDQUOT, WSAEDQUOT)                   /**< Disc quota exceeded. */
#define AH_EEXIST          AH_I_ERR_ONE_OF(EEXIST, 5507)                        /**< Already exists. */
#define AH_EFAULT          AH_I_ERR_ONE_OF(EFAULT, WSAEFAULT)                   /**< Bad pointer. */
#define AH_EFBIG           AH_I_ERR_ONE_OF(EFBIG, 5508)                         /**< File too large. */
#define AH_EHOSTDOWN       AH_I_ERR_ONE_OF(EHOSTDOWN, WSAEHOSTDOWN)             /**< Host down. */
#define AH_EHOSTUNREACH    AH_I_ERR_ONE_OF(EHOSTUNREACH, WSAEHOSTUNREACH)       /**< Host unreachable. */
#define AH_EIDRM           AH_I_ERR_ONE_OF(EIDRM, 5509)                         /**< Identifier removed. */
#define AH_EILSEQ          AH_I_ERR_ONE_OF(EILSEQ, 5510)                        /**< Illegal byte sequence. */
#define AH_EINPROGRESS     AH_I_ERR_ONE_OF(EINPROGRESS, WSAEINPROGRESS)         /**< Operation in progress. */
#define AH_EINTR           AH_I_ERR_ONE_OF(EINTR, WSAEINTR)                     /**< Interrupted. */
#define AH_EINVAL          AH_I_ERR_ONE_OF(EINVAL, WSAEINVAL)                   /**< Invalid argument. */
#define AH_EIO             AH_I_ERR_ONE_OF(EIO, 5511)                           /**< I/O error. */
#define AH_EISCONN         AH_I_ERR_ONE_OF(EISCONN, WSAEISCONN)                 /**< Already connected. */
#define AH_EISDIR          AH_I_ERR_ONE_OF(EISDIR, 5512)                        /**< Is a directory. */
#define AH_ELOOP           AH_I_ERR_ONE_OF(ELOOP, WSAELOOP)                     /**< Too many levels of symbolic links. */
#define AH_EMFILE          AH_I_ERR_ONE_OF(EMFILE, WSAEMFILE)                   /**< File descriptor value too large. */
#define AH_EMLINK          AH_I_ERR_ONE_OF(EMLINK, 5513)                        /**< Too many links. */
#define AH_EMSGSIZE        AH_I_ERR_ONE_OF(EMSGSIZE, WSAEMSGSIZE)               /**< Message too large. */
#define AH_EMULTIHOP       AH_I_ERR_ONE_OF(EMULTIHOP, 5514)                     /**< Incomplete route path. */
#define AH_ENAMETOOLONG    AH_I_ERR_ONE_OF(ENAMETOOLONG, WSAENAMETOOLONG)       /**< Name too long. */
#define AH_ENETDOWN        AH_I_ERR_ONE_OF(ENETDOWN, WSAENETDOWN)               /**< Network is down. */
#define AH_ENETRESET       AH_I_ERR_ONE_OF(ENETRESET, WSAENETRESET)             /**< Connection aborted by network. */
#define AH_ENETUNREACH     AH_I_ERR_ONE_OF(ENETUNREACH, WSAENETUNREACH)         /**< Network unreachable. */
#define AH_ENFILE          AH_I_ERR_ONE_OF(ENFILE, 5515)                        /**< Too many files open in system. */
#define AH_ENOBUFS         AH_I_ERR_ONE_OF(ENOBUFS, WSAENOBUFS)                 /**< No buffer space available. */
#define AH_ENODATA         AH_I_ERR_ONE_OF(ENODATA, 5516)                       /**< No data available. */
#define AH_ENODEV          AH_I_ERR_ONE_OF(ENODEV, 5517)                        /**< No such device. */
#define AH_ENOENT          AH_I_ERR_ONE_OF(ENOENT, 5518)                        /**< No such entry. */
#define AH_ENOEXEC         AH_I_ERR_ONE_OF(ENOEXEC, 5519)                       /**< Executable file format error. */
#define AH_ENOLCK          AH_I_ERR_ONE_OF(ENOLCK, 5520)                        /**< No locks available. */
#define AH_ENOLINK         AH_I_ERR_ONE_OF(ENOLINK, 5521)                       /**< Link severed. */
#define AH_ENOMEM          AH_I_ERR_ONE_OF(ENOMEM, ERROR_NOT_ENOUGH_MEMORY)     /**< Not enough memory. */
#define AH_ENOMSG          AH_I_ERR_ONE_OF(ENOMSG, 5522)                        /**< No such message. */
#define AH_ENOPROTOOPT     AH_I_ERR_ONE_OF(ENOPROTOOPT, WSAENOPROTOOPT)         /**< Protocol not available. */
#define AH_ENOSPC          AH_I_ERR_ONE_OF(ENOSPC, 5523)                        /**< No space left. */
#define AH_ENOSR           AH_I_ERR_ONE_OF(ENOSR, 5524)                         /**< No STREAM resources. */
#define AH_ENOSTR          AH_I_ERR_ONE_OF(ENOSTR, 5525)                        /**< Not a STREAM. */
#define AH_ENOSYS          AH_I_ERR_ONE_OF(ENOSYS, WSASYSCALLFAILURE)           /**< System call unsupported. */
#define AH_ENOTBLK         AH_I_ERR_ONE_OF(ENOTBLK, 5526)                       /**< Not a block device. */
#define AH_ENOTCONN        AH_I_ERR_ONE_OF(ENOTCONN, WSAENOTCONN)               /**< Not connected. */
#define AH_ENOTDIR         AH_I_ERR_ONE_OF(ENOTDIR, 5527)                       /**< Not a directory or a symbolic link to a directory. */
#define AH_ENOTEMPTY       AH_I_ERR_ONE_OF(ENOTEMPTY, 5528)                     /**< Not empty. */
#define AH_ENOTRECOVERABLE AH_I_ERR_ONE_OF(ENOTRECOVERABLE, 5529)               /**< Not recoverable. */
#define AH_ENOTSOCK        AH_I_ERR_ONE_OF(ENOTSOCK, WSAENOTSOCK)               /**< Not a socket. */
#define AH_ENXIO           AH_I_ERR_ONE_OF(ENXIO, 5530)                         /**< No such device or address. */
#define AH_EOPNOTSUPP      AH_I_ERR_ONE_OF(EOPNOTSUPP, WSAEOPNOTSUPP)           /**< Operation not supported. */
#define AH_EOVERFLOW       AH_I_ERR_ONE_OF(EOVERFLOW, 5531)                     /**< Value does not fit in target. */
#define AH_EOWNERDEAD      AH_I_ERR_ONE_OF(EOWNERDEAD, 5532)                    /**< Previous owner died. */
#define AH_EPERM           AH_I_ERR_ONE_OF(EPERM, 5533)                         /**< Not permitted. */
#define AH_EPFNOSUPPORT    AH_I_ERR_ONE_OF(EPFNOSUPPORT, WSAEPFNOSUPPORT)       /**< Protocol family not supported. */
#define AH_EPIPE           AH_I_ERR_ONE_OF(EPIPE, 5534)                         /**< Broken pipe. */
#define AH_EPROTO          AH_I_ERR_ONE_OF(EPROTO, 5535)                        /**< Protocol error. */
#define AH_EPROTONOSUPPORT AH_I_ERR_ONE_OF(EPROTONOSUPPORT, WSAEPROTONOSUPPORT) /**< Protocol not supported. */
#define AH_EPROTOTYPE      AH_I_ERR_ONE_OF(EPROTOTYPE, WSAEPROTOTYPE)           /**< Protocol type wrong. */
#define AH_ERANGE          AH_I_ERR_ONE_OF(ERANGE, 5536)                        /**< Arithmetic result outside accepted range. */
#define AH_EROFS           AH_I_ERR_ONE_OF(EROFS, 5537)                         /**< Read-only file system. */
#define AH_ESHUTDOWN       AH_I_ERR_ONE_OF(ESHUTDOWN, WSAESHUTDOWN)             /**< Has shut down. */
#define AH_ESOCKTNOSUPPORT AH_I_ERR_ONE_OF(ESOCKTNOSUPPORT, WSAESOCKTNOSUPPORT) /**< Socket type not supported. */
#define AH_ESPIPE          AH_I_ERR_ONE_OF(ESPIPE, 5538)                        /**< Broken pipe. */
#define AH_ESRCH           AH_I_ERR_ONE_OF(ESRCH, 5539)                         /**< Not found. */
#define AH_ESTALE          AH_I_ERR_ONE_OF(ESTALE, WSAESTALE)                   /**< Stale. */
#define AH_ETIME           AH_I_ERR_ONE_OF(ETIME, 5540)                         /**< Timeout. */
#define AH_ETIMEDOUT       AH_I_ERR_ONE_OF(ETIMEDOUT, WSAETIMEDOUT)             /**< Timed out. */
#define AH_ETOOMANYREFS    AH_I_ERR_ONE_OF(ETOOMANYREFS, WSAETOOMANYREFS)       /**< Too many references. */
#define AH_ETXTBSY         AH_I_ERR_ONE_OF(ETXTBSY, 5541)                       /**< Text file busy. */
#define AH_EUSERS          AH_I_ERR_ONE_OF(EUSERS, WSAEUSERS)                   /**< Too many users. */
#define AH_EXDEV           AH_I_ERR_ONE_OF(EXDEV, 5542)                         /**< Cross-device link. */
/** @} */

#if AH_IS_DARWIN || defined(AH_DOXYGEN)
/**
 * @name Darwin Errors
 * @{
 */
# define AH_EBADARCH      EBADARCH      /**< Bad CPU type in executable. */
# define AH_EBADEXEC      EBADEXEC      /**< Bad executable. */
# define AH_EBADMACHO     EBADMACHO     /**< Malformed Macho file. */
# define AH_EFTYPE        EFTYPE        /**< Inappropriate file type or format. */
# define AH_ENEEDAUTH     ENEEDAUTH     /**< Need authenticator. */
# define AH_EPROCLIM_D    EPROCLIM      /**< Process limit reached. */
# define AH_EPROCUNAVAIL  EPROCUNAVAIL  /**< Bad procedure for program. */
# define AH_EPROGMISMATCH EPROGMISMATCH /**< Program version wrong. */
# define AH_ESHLIBVERS    ESHLIBVERS    /**< Shared library version mismatch. */
/** @} */
#endif

#if AH_IS_LINUX || defined(AH_DOXYGEN)
/**
 * @name Linux Errors
 * @{
 */
# define AH_ELIBACC  ELIBACC  /**< Needed shared library inaccessible. */
# define AH_ELIBBAD  ELIBBAD  /**< Shared library corrupted. */
# define AH_ELIBEXEC ELIBEXEC /**< Cannot execute shared library. */
# define AH_ELIBMAX  ELIBMAX  /**< Attempting to link in too many shared libraries. */
# define AH_ELIBSCN  ELIBSCN  /**< .lib section in a.out corrupted. */
# define AH_ENONET   ENONET   /**< Not on the network. */
# define AH_ENOTUNIQ ENOTUNIQ /**< Name not unique on network. */
# define AH_EREMCHG  EREMCHG  /**< Remote address changed. */
# define AH_ESTRPIPE ESTRPIPE /**< Streams pipe error. */
/** @} */
#endif

#if AH_IS_WIN32 || defined(AH_DOXYGEN)
/**
 * @name Win32 Errors
 * @{
 */
# define AH_EDISCON             WSAEDISCON                /**< Disconneted. */
# define AH_EHOSTNOTFOUND       WSAHOST_NOT_FOUND         /**< Host not found. */
# define AH_EPROVIDERFAILEDINIT WSAEPROVIDERFAILEDINIT    /**< Network service provider failed to initialize. */
# define AH_ESECHOSTNOTFOUND    WSA_SECURE_HOST_NOT_FOUND /**< Secure host not found. */
# define AH_ESYSNOTREADY        WSASYSNOTREADY            /**< Networking system not ready. */
# define AH_EPROCLIM_W          WSAEPROCLIM               /**< Process limit reached. */
/** @} */
#endif

/**
 * Writes human-readable representation of @a err to @a buf.
 *
 * If @a err is a custom error code, as listed in this file, or zero, the
 * representation will be in the English language. If @a err is any other error
 * code, the representation will adhere to the current platform locale.
 *
 * @param err Error code to represent as text.
 * @param buf String buffer to receive string representation.
 * @param size Size of @a buf, in bytes.
 *
 * @note @a buf will be NULL-terminated as long as @a size is greater than or
 *       equal to @c 1. If the text representation does not fit, it will be
 *       truncated.
 *
 * @note This function is thread safe on all supported platforms.
 */
ah_extern void ah_strerror_r(ah_err_t err, char* buf, size_t size);

#endif
