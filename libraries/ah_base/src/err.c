// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
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

#define AH_I_ERR_E(NAME, CODE, STRING) \
 case AH_E##NAME:                      \
  string = (STRING);                   \
  break;

#if AH_IS_DARWIN || AH_IS_LINUX

        AH_I_ERR_MAP_CUSTOM(AH_I_ERR_E)

    default:
        (void) strerror_r(err, buf, size);
        return;

#elif AH_IS_WIN32

        AH_I_ERR_MAP_CUSTOM(AH_I_ERR_E)

    default:
        const WORD flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        (void) FormatMessageA(flags, NULL, err, 0u, (LPTSTR) buf, size, NULL);
        return;

#else

        AH_I_ERR_MAP(AH_I_ERR_E)

    default:
        string = "unknown error";
        break;

#endif

#undef AH_I_ERR_E
    }

    (void) strncpy(buf, string, size);
}
