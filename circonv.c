#include "constants.h"
#include "pass_types.h"
#include "circonv.h"

/* Cyclic convolution mod p. c = a*b (mod p)
 * Assumes all coefficient vectors are initialized and of length N.
 * Assumes c is zero, otherwise computes c += a*b (mod p).
 */
int
circonv(int64 *c, const int64 *a, const int64 *b)
{
  int64 i;
  int64 j;

  for (i = 0; i < PASS_N; i++) {
    if (a[i] == 0) continue;

    for (j = i; j < PASS_N; j++) {
      c[j] += (a[i] * b[j-i]);
    }
    for (j = 0; j < i; j++) {
      c[j] += (a[i] * b[j-i+PASS_N]);
    }
  }
}


int
bsparseconv (int64 *c, const int64 *a, const b_sparse_poly *b)
{
  int64 i = 0;
  int64 j = 0;
  int64 k = 0;

  for (i = 0; i < PASS_b; i++) {
    k = b->ind[i];

    if(b->val[i] == 1) {
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
}

