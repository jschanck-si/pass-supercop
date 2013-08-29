/*
 * CPASSREF/bench.c
 *
 *  Copyright 2013 John M. Schanck
 *
 *  This file is part of CPASSREF.
 *
 *  CPASSREF is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
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

#include "constants.h"
#include "pass_types.h"
#include "hash.h"
#include "ntt.h"
#include "pass.h"

#define TRIALS 100000

#define MLEN 256


static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}


int
main(int argc, char **argv)
{
  int i;
  int count;

  int64 key[PASS_N];
  int64 *z;
  unsigned char in[MLEN+1] = {0};
  unsigned char h[HASH_BYTES];

  memset(in, '0', MLEN);
  z = malloc(PASS_N * sizeof(int64));

  init_fast_prng();

  if(ntt_setup() == -1) {
    fprintf(stderr,
        "ERROR: Could not initialize FFTW. Bad wisdom?\n");
    exit(EXIT_FAILURE);
  }

  printf("Parameters:\n\t N: %d, p: %d, g: %d, k: %d, b: %d, t: %d\n\n",
      PASS_N, PASS_p, PASS_g, PASS_k, PASS_b, PASS_t);

  printf("Generating %d signatures %s\n", TRIALS,
          VERIFY ? "and verifying" : "and not verifying");

  gen_key(key);

#if DEBUG
  printf("sha512(key): ");
  crypto_hash_sha512(h, (unsigned char*)key, sizeof(int64)*PASS_N);
  for(i=0; i<HASH_BYTES; i++) {
    printf("%.2x", h[i]);
  }
  printf("\n");
#endif

#if VERIFY
  int nbver = 0;

  int64 pubkey[PASS_N] = {0};
  gen_pubkey(pubkey, key);
#endif

  clock_t c0,c1;
  unsigned long long rdtsc0, rdtsc1;
  c0 = clock();

  count = 0;
  rdtsc0 = rdtsc();
  for(i=0; i<TRIALS; i++) {
   in[(i&0xff)]++; /* Hash a different message each time */
   count += sign(h, z, key, in, MLEN);

#if VERIFY
   nbver += (VALID == verify(h, z, pubkey, in, MLEN));
#endif
  }
  rdtsc1 = rdtsc();
  printf("\n");

  c1 = clock();
  printf("Total attempts: %d\n",  count);
#if VERIFY
  printf("Valid signatures: %d/%d\n",  nbver, TRIALS);
#endif
  printf("Attempts/sig: %f\n",  (((float)count)/TRIALS));
  printf("Time/sig: %fs\n", (float) (c1 - c0)/(TRIALS*CLOCKS_PER_SEC));
  printf("Average cycles per signature: %Lf\n", ((long double)rdtsc1 - rdtsc0)/TRIALS);

#if DEBUG
  printf("\n\nKey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) key[i]));

  #if VERIFY
  printf("\n\nPubkey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) pubkey[i]));
  printf("\n");
  #endif

  printf("\n\nz: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) z[i]));
  printf("\n");
#endif

  free(z);
  ntt_cleanup();
  return 0;
}

