// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BASE_H_
#define AH_BASE_H_

/**
 * @file
 * Compile-time metadata.
 *
 * This file provides details determined when this library is compiled.
 *
 * @warning If you compile this library in any other way than the one officially
 *          supported, the macros defined here may present arbitrary default
 *          values when used.
 */

#include "internal/_base.gen"

/**
 * Constant string representation of the source code version from which this
 * library was compiled.
 */
#define AH_BASE_COMMIT_STR AH_I_BASE_COMMIT_STR

/**
 * Constant string identifier representing the platform for which this library
 * was compiled.
 */
#define AH_BASE_PLATFORM_STR AH_I_BASE_PLATFORM_STR

/**
 * Major version of the base library, represented by an unsigned integer
 * literal.
 */
#define AH_BASE_VERSION_MAJOR AH_I_BASE_VERSION_MAJOR

/**
 * Minor version of the base library, represented by an unsigned integer
 * literal.
 */
#define AH_BASE_VERSION_MINOR AH_I_BASE_VERSION_MINOR

/**
 * Patch version of the base library, represented by an unsigned integer
 * literal.
 */
#define AH_BASE_VERSION_PATCH AH_I_BASE_VERSION_PATCH

/**
 * Constant string representation of the base library version.
 */
#define AH_BASE_VERSION_STR AH_I_BASE_VERSION_STR

#endif
