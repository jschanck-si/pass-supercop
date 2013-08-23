/*
 * CPASSREF/poly.c
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

#include "constants.h"
#include "pass_types.h"
#include "poly.h"

int
poly_cmod(int64 *a, int64 q)
{
  int64 i;
  int64 tmp;
  int64 qo2 = (q-1)/2;
  for (i=0; i<PASS_N; i++) {
    tmp = a[i];
    if (tmp >= 0) {
      tmp %= q;
    } else {
      tmp = q - ((-tmp) % q);
    }
    if (tmp > qo2)
      tmp -= q;
    a[i] = tmp;
  }

  return 0;
}
