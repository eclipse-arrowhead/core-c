// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BASE_H_
#define AH_BASE_H_

/**
 * @file
 * Base library metadata.
 *
 * This file provides details about this library.
 */

#include "defs.h"

/**
 * Gets human-readable representation of version of the Base library.
 *
 * @return Constant string representation of version.
 */
ah_extern const char* ah_base_lib_version_str(void);

/**
 * Gets major version of the Base library.
 *
 * @return Major version indicator.
 */
ah_extern unsigned short ah_base_lib_version_major(void);

/**
 * Gets minor version of the Base library.
 *
 * @return Minor version indicator.
 */
ah_extern unsigned short ah_base_lib_version_minor(void);

/**
 * Gets patch version of the Base library.
 *
 * @return Patch version indicator.
 */
ah_extern unsigned short ah_base_lib_version_patch(void);

#endif
