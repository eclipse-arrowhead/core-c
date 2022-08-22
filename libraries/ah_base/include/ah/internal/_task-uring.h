// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_URING_TASK_H_
#define AH_INTERNAL_URING_TASK_H_

#include "../time.h"

#define AH_I_TASK_PLATFORM_FIELDS \
 struct ah_time _baseline;        \
 struct ah_i_loop_evt* _evt;

#endif
