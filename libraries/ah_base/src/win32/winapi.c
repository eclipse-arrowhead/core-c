#include "winapi.h"

#include "ah/abort.h"
#include "ah/err.h"

#include <winsock2.h>

#pragma comment(lib, "ws2_32")

ah_err_t ah_i_winapi_get_wsa_fn(SOCKET fd, GUID* guid, void** fn)
{
    const DWORD control_code = SIO_GET_EXTENSION_FUNCTION_POINTER;
    DWORD size;

    int res = WSAIoctl(fd, control_code, guid, sizeof(GUID), (void*) fn, sizeof(void*), &size, NULL, NULL);
    if (res == SOCKET_ERROR) {
        return WSAGetLastError();
    }

    return AH_ENONE;
}

LPTSTR ah_i_winapi_strerror(DWORD err)
{
    LPTSTR buf;
    WORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    (void) FormatMessageA(flags, NULL, err, 0u, (LPTSTR) &buf, 1u, NULL);
    return buf;
}
