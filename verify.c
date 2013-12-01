/*
 * CPASSREF/verify.c
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

#include <string.h>

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "hash.h"
#include "formatc.h"
#include "ntt.h"
#include "pass.h"


#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

int
crypto_sign_pass769_ref_open(
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

  crypto_hash_sha512(msg_digest, m, *mlen);
  hash(h2, Fz, msg_digest);

  for(i=0; i<HASH_BYTES; i++) {
    if(h2[i] != h[i])
      return INVALID;
  }

  return VALID;
}
