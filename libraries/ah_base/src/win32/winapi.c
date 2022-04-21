#include "winapi.h"

#include "ah/abort.h"
#include "ah/err.h"

#pragma comment(lib, "ws2_32")

static BOOL CALLBACK s_init(PINIT_ONCE init_once, PVOID param, PVOID* ctx);
static void s_load_wsa_fn(SOCKET fd, GUID* guid, const char* name, void** fn);

INIT_ONCE s_once = INIT_ONCE_STATIC_INIT;

LPFN_ACCEPTEX win_AcceptEx;
LPFN_CONNECTEX win_ConnectEx;
LPFN_GETACCEPTEXSOCKADDRS win_GetAcceptExSockaddrs;
LPFN_WSARECVMSG win_WSARecvMsg;

void ah_i_winapi_init(void)
{
    WSADATA wsa_data;
    int res = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (res != 0) {
        ah_abortf("failed to startup WSA; %s", ah_strerror(res));
    }

    if (!InitOnceExecuteOnce(&s_once, s_init, NULL, NULL)) {
        ah_abortf("failed to initialize WIN32; %*.s", ah_i_winapi_strerror(GetLastError()));
    }
}

static BOOL CALLBACK s_init(PINIT_ONCE init_once, PVOID param, PVOID* ctx)
{
    (void) init_once;
    (void) param;
    (void) ctx;

    const SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET) {
        ah_abortf("failed to create bootstrap socket; %*.s", ah_i_winapi_strerror(WSAGetLastError()));
    }

    s_load_wsa_fn(fd, &(GUID) WSAID_ACCEPTEX, "AcceptEx", (void**) &win_AcceptEx);
    s_load_wsa_fn(fd, &(GUID) WSAID_CONNECTEX, "ConnectEx", (void**) &win_ConnectEx);
    s_load_wsa_fn(fd, &(GUID) WSAID_GETACCEPTEXSOCKADDRS, "GetAcceptExSockaddrs", (void**) &win_GetAcceptExSockaddrs);
    s_load_wsa_fn(fd, &(GUID) WSAID_WSARECVMSG, "WSARecvMsg", (void**) &win_WSARecvMsg);

    closesocket(fd);

    return TRUE;
}

static void s_load_wsa_fn(SOCKET fd, GUID* guid, const char* name, void** fn)
{
    const DWORD control_code = SIO_GET_EXTENSION_FUNCTION_POINTER;
    DWORD size;

    int res = WSAIoctl(fd, control_code, guid, sizeof(GUID), (void*) fn, sizeof(void*), &size, NULL, NULL);
    if (res != SOCKET_ERROR) {
        return;
    }

    ah_abortf("failed to load WIN32 function \"%s\"; %*.s", name, ah_i_winapi_strerror(WSAGetLastError()));
}

LPTSTR ah_i_winapi_strerror(DWORD err)
{
    LPTSTR buf;
    WORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    (void) FormatMessageA(flags, NULL, err, 0u, (LPTSTR) &buf, 1u, NULL);
    return buf;
}

void ah_i_winapi_term(void)
{
    (void) WSACleanup();
}
