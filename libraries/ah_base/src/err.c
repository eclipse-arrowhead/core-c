// SPDX-License-Identifier: EPL-2.0

#include <ah/err.h>
#include <string.h>

#if AH_IS_WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

ah_extern void ah_strerror_r(ah_err_t err, char* buf, size_t size)
{
    const char* string;

    switch (err) {
    case AH_ENONE:
        string = "no error";
        break;

    case AH_EDEP:
        string = "dependency failed";
        break;

    case AH_EDUP:
        string = "duplicate exists";
        break;

    case AH_EEOF:
        string = "unexpected end";
        break;

    case AH_EINTERN:
        string = "internal error";
        break;

    case AH_ERECONN:
        string = "reconnecting";
        break;

    case AH_ESTATE:
        string = "state invalid";
        break;

    case AH_ESYNTAX:
        string = "syntax invalid";
        break;

#if AH_IS_DARWIN || AH_IS_LINUX

    default:
        (void) strerror_r(err, buf, size);
        return;

#elif AH_IS_WIN32

    case AH_E2BIG:
        string = "argument list too long";
        break;

    case AH_EBADMSG:
        string = "bad message";
        break;

    case AH_EBUSY:
        string = "device or resource busy";
        break;

    case AH_ECHILD:
        string = "no child processes";
        break;

    case AH_EDEADLK:
        string = "deadlock would occur";
        break;

    case AH_EDOM:
        string = "arithmetic argument outside accepted domain";
        break;

    case AH_EEXIST:
        string = "already exists";
        break;

    case AH_EFBIG:
        string = "file too large";
        break;

    case AH_EIDRM:
        string = "identifier removed";
        break;

    case AH_EILSEQ:
        string = "illegal byte sequence";
        break;

    case AH_EIO:
        string = "I/O error";
        break;

    case AH_EISDIR:
        string = "is a directory";
        break;

    case AH_EMLINK:
        string = "too many links";
        break;

    case AH_EMULTIHOP:
        string = "incomplete route path";
        break;

    case AH_ENFILE:
        string = "too many files open in system";
        break;

    case AH_ENODATA:
        string = "no data available";
        break;

    case AH_ENODEV:
        string = "no such device";
        break;

    case AH_ENOENT:
        string = "no such entry";
        break;

    case AH_ENOEXEC:
        string = "executable file format error";
        break;

    case AH_ENOLCK:
        string = "no locks available";
        break;

    case AH_ENOLINK:
        string = "link severed";
        break;

    case AH_ENOMSG:
        string = "no such message";
        break;

    case AH_ENOSPC:
        string = "no space left";
        break;

    case AH_ENOSR:
        string = "no STREAM resources";
        break;

    case AH_ENOSTR:
        string = "not a STREAM";
        break;

    case AH_ENOTBLK:
        string = "not a block device";
        break;

    case AH_ENOTDIR:
        string = "not a directory or a symbolic link to a directory";
        break;

    case AH_ENOTEMPTY:
        string = "not empty";
        break;

    case AH_ENOTRECOVERABLE:
        string = "not recoverable";
        break;

    case AH_ENXIO:
        string = "no such device or address";
        break;

    case AH_EOVERFLOW:
        string = "value does not fit in target";
        break;

    case AH_EOWNERDEAD:
        string = "previous owner died";
        break;

    case AH_EPERM:
        string = "not permitted";
        break;

    case AH_EPIPE:
        string = "broken pipe";
        break;

    case AH_EPROTO:
        string = "protocol error";
        break;

    case AH_ERANGE:
        string = "arithmetic result outside accepted range";
        break;

    case AH_EROFS:
        string = "read-only file system";
        break;

    case AH_ESPIPE:
        string = "broken pipe";
        break;

    case AH_ESRCH:
        string = "not found";
        break;

    case AH_ETIME:
        string = "timeout";
        break;

    case AH_ETXTBSY:
        string = "text file busy";
        break;

    case AH_EXDEV:
        string = "cross-device link";
        break;

    default: {
        if (size > MAXDWORD) {
            size = MAXDWORD;
        }
        const WORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        (void) FormatMessageA(flags, NULL, err, 0u, (LPTSTR) buf, (DWORD) size, NULL);
        return;
    }

#endif

#undef AH_I_ERR_E
    }

#if AH_IS_WIN32
    errno_t win32_err = strncpy_s(buf, size, string, _TRUNCATE);
    if (win32_err != 0 && win32_err != STRUNCATE && size > 0u) {
        buf[0u] = '\0';
    }
#else
    (void) strncpy(buf, string, size);
#endif
}
