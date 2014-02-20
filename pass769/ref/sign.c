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

#include "crypto_sign.h"

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
static int randpos = RAND_LEN;

int
crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  int i = 0;
  uint16 r = 0;
  int64 Ff[PASS_N];
  int64 f[PASS_N];

  while(i < PASS_N) {
    if(randpos >= RAND_LEN) {
      fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
      randpos = 0;
    }
    if(!r) r = randpool[randpos++];
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


int
crypto_sign(
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

int
crypto_sign_open(
    unsigned char *m, unsigned long long *mlen,
    const unsigned char *sm, unsigned long long smlen,
    const unsigned char *pk)
{
  int i;
  b_sparse_poly c;
  int64 Fc[PASS_N];
  int64 Fz[PASS_N];
  int64 z[PASS_N];
  uint16 zi;

  const unsigned char *h = sm;

  unsigned char msg_digest[HASH_BYTES];
  unsigned char h2[HASH_BYTES];

  *mlen = smlen - crypto_sign_BYTES;

  for(i=0; i<PASS_N; i++) {
    zi = ((uint16) *(sm+HASH_BYTES+2*i))<<8;
    zi += ((uint16) *(sm+HASH_BYTES+2*i+1));
    z[i] = (int64) zi - (1<<15);
  }

  if(reject(z))
    return INVALID;

  CLEAR(c.val);
  formatc(&c, h);

  ntt(Fc, c.val);
  ntt(Fz, z);

  for(i=0; i<PASS_t; i++) {
    Fz[S[i]] -= Fc[S[i]] * ((int32 *)pk)[i];
  }

  poly_cmod(Fz);

  crypto_hash_sha512(msg_digest, sm+crypto_sign_BYTES, *mlen);
  hash(h2, Fz, msg_digest);

  for(i=0; i<HASH_BYTES; i++) {
    if(h2[i] != h[i])
      return INVALID;
  }

  for(i=0; i<*mlen; i++) {
    m[i] = sm[i + crypto_sign_BYTES];
  }

  return VALID;
}

int
mknoise(int64 *y)
{
  int i = 0;
  int x;
  while(i < PASS_N) {
    if(randpos >= RAND_LEN) {
      fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
      randpos = 0;
    }
    x = randpool[randpos++];
    if(x >= UNSAFE_RAND_k) continue;
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

