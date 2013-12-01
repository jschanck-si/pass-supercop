/*
 * CPASSREF/key.c
 *
 *  Copyright 2013 John M. Schanck
 *
 *  This file is part of CPASSREF.
 *
 *  CPASSREF is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  CPASSREF is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with CPASSREF.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>

#include "constants.h"
#include "pass_types.h"
#include "ntt.h"
#include "randombytes.h"
#include "pass.h"


#define RAND_LEN (64)

int crypto_sign_pass769_ref_keypair(unsigned char *pk, unsigned char *sk)
{
  int i = 0;
  int j = 0;
  uint64 r = 0;
  uint64 pool[RAND_LEN];
  int64 Ff[PASS_N];
  int64 f[PASS_N];

  randombytes((unsigned char*)pool, RAND_LEN*sizeof(uint64));

  while(i < PASS_N) {
    if(j == RAND_LEN) {
      randombytes((unsigned char*)pool, RAND_LEN*sizeof(uint64));
      j = 0;
    }
    if(!r) r = pool[j++];
    switch(r & 0x03) {
      case 1: f[i] = -1; break;
      case 2: f[i] =  0; break;
      case 3: f[i] =  1; break;
      default:  r >>= 2; continue;
    }
    sk[i] = (char) f[i];
    r >>= 2;
    i++;
  }

  ntt((int64 *)Ff, f);
  for(i=0; i<PASS_t; i++)
    ((int32 *)pk)[i] = (int32) Ff[S[i]];



 return 0;
}
