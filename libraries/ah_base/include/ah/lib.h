// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LIB_H_
#define AH_LIB_H_

/**
 * @file
 * Library metadata.
 *
 * This file provides details about the library that is determined when the
 * library is compiled.
 */

#include "defs.h"

/**
 * Gets human-readable representation of the source code version from which this
 * library was compiled.
 *
 * @return Constant string representation of source code version.
 */
ah_extern const char* ah_lib_commit_str(void);

/**
 * Gets human-readable identifier representing the platform for which this
 * library was compiled.
 *
 * @return Constant string representation of targeted platform.
 */
ah_extern const char* ah_lib_platform_str(void);

#endif
