// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_ABORT_H_
#define AH_ABORT_H_

#include "defs.h"

ah_extern ah_noreturn void ah_abort(void);
ah_extern ah_noreturn void ah_abortf(const char* format, ...);
#if AH_IS_WIN32
ah_extern ah_noreturn void ah_abort_with_last_win32_error(const char* message);
#endif

#endif
