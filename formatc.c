#include <stdlib.h>

#include "constants.h"
#include "pass_types.h"
#include "formatc.h"

/* XXX: Temporary hack to get up and running fast. Need a secure FormatC function !!! */

int
formatc(b_sparse_poly *c, const unsigned char *digest)
{
  int i;
  int j;
  int ok;
  int64 indx;
  unsigned int seed;
  seed  = ((digest[0] & 0xff) << 24);
  seed |= ((digest[1] & 0xff) << 16);
  seed |= ((digest[2] & 0xff) << 8);
  seed |= ((digest[3] & 0xff));

  srand(seed);

  i=0;
  while(i < PASS_b){
    indx = rand() % PASS_N;
    ok = 1;
    for(j=0; j<i; j++) {
      if(c->ind[j] == indx) {
        ok = 0;
        break;
      }
    }
    if(ok) {
      c->ind[i] = indx;
      c->val[i] = 2 * (rand() & 1) - 1;
      i++;
    }
  }

  return 0;
}

