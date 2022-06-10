// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_CONF_H_
#define AH_CONF_H_

#if !defined(AH_CONF_INCLUDE) && defined(__has_include) && __has_include("ah-base-conf-custom.h")
# define AH_CONF_INCLUDE "ah-base-conf-custom.h"
#endif

#ifdef AH_CONF_INCLUDE
# include AH_CONF_INCLUDE
#endif

#if !defined(AH_CONF_IS_CONSTRAINED) && defined(__arm__) && !defined(__aarch64__)
# define AH_CONF_IS_CONSTRAINED 1
#endif

#ifndef AH_CONF_IS_CONSTRAINED
# define AH_CONF_IS_CONSTRAINED 0
#endif

#endif
