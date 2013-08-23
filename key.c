/*
 * CPASSREF/key.c
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

