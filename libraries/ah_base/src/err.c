// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include <ah/err.h>

ah_extern const char* ah_strerror(ah_err_t err)
{
    const char* string;

    switch (err) {
    case AH_ENONE:
        string = "no error";
        break;

#define AH_I_ERR_E(NAME, CODE, STRING) \
 case AH_E##NAME:                      \
  string = (STRING);                   \
  break;

        AH_I_ERR_MAP(AH_I_ERR_E)

#undef AH_I_ERR_E

    default:
        string = "unknown error";
        break;
    }

    return string;
}
