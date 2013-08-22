#include <stdlib.h>

#include "constants.h"
#include "pass_types.h"
#include "ntt.h"
#include "pass.h"

int
gen_key(int64 *f)
{
  int i = 0;
  unsigned int r = 0;
  while(i < PASS_N) {
    if(!r) r = (unsigned int) rand();
    switch(r & 0x03) {
      case 0: f[i] = -1; break;
      case 1: f[i] =  0; break;
      case 2: f[i] =  1; break;
      default:  r >>= 2; continue;
    }
    r >>= 2;
    i++;
  }

  return 0;
}

int
gen_pubkey(int64 *pkey, int64 *skey)
{
  int i;
  int64 Ff[PASS_N] = {0};
  ntt(Ff, skey);
  for(i=0; i<PASS_t; i++)
    pkey[S[i]] = Ff[S[i]];

  return 0;
}

