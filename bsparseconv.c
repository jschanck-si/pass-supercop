#include "constants.h"
#include "pass_types.h"
#include "bsparseconv.h"

int
bsparseconv (int64 *c, const int64 *a, const b_sparse_poly *b)
{
  int64 i = 0;
  int64 j = 0;
  int64 k = 0;

  for (i = 0; i < PASS_b; i++) {
    k = b->ind[i];

    if(b->val[k] > 0) {
      for (j = k; j < PASS_N; j++) {
        c[j] += a[j-k];
      }
      for (j = 0; j < k; j++) {
        c[j] += a[j-k+PASS_N];
      }
    }else{ /* b->val[i] == -1 */
      for (j = k; j < PASS_N; j++) {
        c[j] -= a[j-k];
      }
      for (j = 0; j < k; j++) {
        c[j] -= a[j-k+PASS_N];
      }
    }
  }

  return 0;
}

