// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_WINAPI_H_
#define SRC_WINAPI_H_

#include "ah/defs.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <winsock2.h>

ah_err_t ah_i_winapi_get_wsa_fn(SOCKET fd, GUID* guid, void** fn);

// Free returned string with LocalFree().
LPTSTR ah_i_winapi_strerror(DWORD err);

#endif
