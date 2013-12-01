/*
 * CPASSREF/sign.c
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

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "formatc.h"
#include "bsparseconv.h"
#include "ntt.h"
#include "hash.h"
#include "fastrandombytes.h"
#include "pass.h"


#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

#define RAND_LEN (4096)

static uint16 randpool[RAND_LEN];
static int randpos;

int
init_fast_prng()
{
  fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
  randpos = 0;

  return 0;
}

int
mknoise(int64 *y)
{
  int i = 0;
  int x;
  while(i < PASS_N) {
    if(randpos == RAND_LEN) {
      fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
      randpos = 0;
    }
    x = randpool[randpos++];
    if(x >= SAFE_RAND_k) continue;
    x &= (2*PASS_k + 1);

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
    if(llabs(z[i]) > (PASS_k - PASS_b))
      return 1;
  }

  return 0;
}

int
crypto_sign_pass769_ref(
    unsigned char *sm, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk)
{
  int i;
  b_sparse_poly c;
  int64 y[PASS_N];
  int64 Fy[PASS_N];
  uint16 zi;
  unsigned char msg_digest[HASH_BYTES];
  unsigned char h[HASH_BYTES];

  crypto_hash_sha512(msg_digest, m, mlen);

  do {
    //CLEAR(Fy);

    mknoise(y);
    ntt(Fy, y);
    hash(h, Fy, msg_digest);

    CLEAR(c.val);
    formatc(&c, h);

    /* z = y += f*c */
    bsparseconv(y, (const char *)sk, &c);
    /* No modular reduction required. */

  } while (reject(y));

  memcpy(sm, h, HASH_BYTES);
  *smlen = HASH_BYTES;

  for(i=0; i<PASS_N; i++) {
    zi = y[i] + (1<<15);
    sm[HASH_BYTES + 2*i] = (zi >> 8);
    sm[HASH_BYTES + 2*i + 1] = (zi & 0xff);
  }
  *smlen += 2*PASS_N;

  memcpy(sm+(*smlen), m, mlen);
  *smlen += mlen;

  return 0;
}
