/*
 * CPASSREF/sign.c
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

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "formatc.h"
#include "bsparseconv.h"
#include "ntt.h"
#include "hash.h"
#include "pass.h"


#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

int
mknoise(int64 *y)
{
  int i = 0;
  int x;
  while(i < PASS_N) {
    x = rand() & (2*PASS_k + 1); // Should be power of 2 - 1...

    if(x == SAFE_RAND_k) continue;

    y[i] = x - PASS_k;
    i++;
  }

  return 0;
}

int
reject(const int64 *z)
{
  int i;

  for(i=0; i<PASS_N; i++) {
    if(abs(z[i]) > (PASS_k - PASS_b))
      return 1;
  }

  return 0;
}

int
sign(unsigned char *h, int64 *z, const int64 *key,
    const unsigned char *message, const int msglen)
{
  int count;
  b_sparse_poly c;
  int64 y[PASS_N];
  int64 Fy[PASS_N];
  unsigned char msg_digest[HASH_BYTES];

  crypto_hash_sha512(msg_digest, message, msglen);

  count = 0;
  do {
    CLEAR(Fy);

    mknoise(y);
    ntt(Fy, y);
    hash(h, Fy, msg_digest);

    CLEAR(c.val);
    formatc(&c, h);

    /* z = y += f*c */
    bsparseconv(y, key, &c);
    /* No modular reduction required. */

    count++;
  } while (reject(y));

#if DEBUG
  int i;
  printf("\n\ny: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) y[i]));
  printf("\n");

  printf("\n\nFy: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) Fy[i]));
  printf("\n");

  printf("\n\nc: ");
  for(i=0; i<PASS_b; i++)
    printf("(%lld, %lld) ", (long long int) c.ind[i],
        (long long int) c.val[c.ind[i]]);
  printf("\n");
#endif

  memcpy(z, y, PASS_N*sizeof(int64));

  return count;
}

