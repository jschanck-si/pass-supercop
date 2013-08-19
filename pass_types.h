/* Require:
 *    constants.h
 */

#ifndef CPASSREF_TYPES_H_
#define CPASSREF_TYPES_H_

#include <stdint.h>

typedef int64_t int64;

typedef struct {
  int64 ind[PASS_b];
  int64 val[PASS_b];
} b_sparse_poly;

#endif
