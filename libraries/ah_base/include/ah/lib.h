// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_LIB_H_
#define AH_LIB_H_

/// \brief Library metadata.
/// \file
///
/// This file provides details about the library that is determined when the
/// library is compiled.

#include "defs.h"

/// \brief Gets human-readable representation of the source code version from
///        which this library was compiled.
///
/// \return Constant string representation of source code version.
ah_extern const char* ah_lib_commit_str(void);

/// \brief Gets human-readable identifier representing the platform for which
///        this library was compiled.
///
/// \return Constant string representation of targeted platform.
ah_extern const char* ah_lib_platform_str(void);

#endif
