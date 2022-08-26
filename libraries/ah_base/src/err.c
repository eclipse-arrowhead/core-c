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

    default:
        const WORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        (void) FormatMessageA(flags, NULL, err, 0u, (LPTSTR) buf, size, NULL);
        return;

#endif

#undef AH_I_ERR_E
    }

    (void) strncpy(buf, string, size);
}
