// SPDX-License-Identifier: EPL-2.0

#ifndef AH_META_H_
#define AH_META_H_

/**
 * @file
 * Compile-time metadata.
 *
 * This file provides details determined when the library is compiled.
 */

#include "defs.h"

/**
 * Gets human-readable representation of the source code version from which this
 * library was compiled.
 *
 * @return Constant string representation of source code version.
 */
ah_extern const char* ah_meta_commit_str(void);

/**
 * Gets human-readable identifier representing the platform for which this
 * library was compiled.
 *
 * @return Constant string representation of targeted platform.
 */
ah_extern const char* ah_meta_platform_str(void);

#endif
