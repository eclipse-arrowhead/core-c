// SPDX-License-Identifier: EPL-2.0

#include "ah/lib.h"

#include "ah/defs.h"
#include "ah_i_git_metadata.h"

ah_extern const char* ah_lib_commit_str(void)
{
    return AH_I_GIT_DESCRIBE_ALWAYS;
}

ah_extern const char* ah_lib_platform_str(void)
{
#if AH_IS_DARWIN
    return "darwin";
#elif AH_IS_LINUX
    return "linux";
#elif AH_IS_WIN32
    return "win32";
#else
    return "unknown";
#endif
}
