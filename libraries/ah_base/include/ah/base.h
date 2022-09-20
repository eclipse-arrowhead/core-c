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
 *          values when used. If the used compiler does not support
 *          @c __has_include, a generated file may be missing, causing
 *          compilation to fail unless you provide a substitute.
 */

#if defined(__has_include)
# if __has_include("internal/_base.gen")
#  include "internal/_base.gen"
# else
#  define AH_I_BASE_COMMIT_STR    "unknown"
#  define AH_I_BASE_PLATFORM_STR  "unknown"
#  define AH_I_BASE_VERSION_MAJOR 0u
#  define AH_I_BASE_VERSION_MINOR 0u
#  define AH_I_BASE_VERSION_PATCH 0u
#  define AH_I_BASE_VERSION_STR   "0.0.0"
# endif
#else
# include "internal/_base.gen"
#endif

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
