// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_BUF_H_
#define AH_INTERNAL_BUF_H_

#include "../defs.h"

#if AH_HAS_POSIX
#    include "_buf-posix.h"
#elif AH_IS_WIN32
#    include "_buf-win32.h"
#endif

#define AH_I_BUF_FIELDS AH_I_BUF_PLATFORM_FIELDS

#endif
