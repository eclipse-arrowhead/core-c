// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include <ah/defs.h>
#include <ah/lib.h>
#include <ah_i_git_metadata.h>

ah_extern const char* ah_lib_commit_str()
{
    return AH_I_GIT_DESCRIBE_ALWAYS;
}

ah_extern const char* ah_lib_platform_str()
{
#if AH_IS_ANDROID
    return "android";
#elif AH_IS_DARWIN
    return "darwin";
#elif AH_IS_LINUX
    return "linux";
#elif AH_IS_WIN32
    return "win32";
#else
    return "unknown";
#endif
}
