#include "constants.h"
#include "pass_types.h"
#include "poly.h"

int
poly_cmod(int64 *a, int64 q)
{
  int64 i;
  int64 tmp;
  int64 qo2 = (q-1)/2;
  for (i=0; i<PASS_N; i++) {
    tmp = a[i];
    if (tmp >= 0) {
      tmp %= q;
    } else {
      tmp = q - ((-tmp) % q);
    }
    if (tmp > qo2)
      tmp -= q;
    a[i] = tmp;
  }

  return 0;
}
