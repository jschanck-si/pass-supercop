/*
 * CPASSREF/bench.c
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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "constants.h"
#include "pass_types.h"
#include "hash.h"
#include "ntt.h"
#include "pass.h"

#ifndef VERIFY
#define VERIFY 1
#endif

#ifndef TRIALS
#define TRIALS 10000
#endif

#define MLEN 64


int
main(int argc, char **argv)
{
  int i;

  unsigned char in[MLEN];
  unsigned char *sm; //[TRIALS * (CRYPTO_BYTES + MLEN)];
  unsigned long long smlen;

  unsigned long long mlen = MLEN;

  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  sm = (unsigned char *) malloc(TRIALS * (CRYPTO_BYTES + MLEN));

  memset(in, '0', mlen);

  crypto_sign_keypair(pk, sk);

  clock_t c0,c1;
  c0 = clock();
  for(i=0; i<TRIALS; i++) {
   in[(i&0x3f)]++; /* Hash a different message each time */
   mlen = MLEN;
   crypto_sign(sm+i*(CRYPTO_BYTES + MLEN), &smlen, in, mlen, sk);
  }
  c1 = clock();

  printf("\n");
  printf("Time/sig: %fs\n", (float) (c1 - c0)/(TRIALS*CLOCKS_PER_SEC));

  memset(in, '0', mlen);
  c0 = clock();
  for(i=0; i<TRIALS; i++) {
   in[(i&0x3f)]++; /* Hash a different message each time */
   mlen = MLEN;
   if(VALID != crypto_sign_open(in, &mlen, sm+i*(CRYPTO_BYTES + MLEN), smlen, pk))
     exit(1);
  }
  c1 = clock();

  printf("Time/ver: %fs\n", (float) (c1 - c0)/(TRIALS*CLOCKS_PER_SEC));

  free(sm);
  return 0;
}

