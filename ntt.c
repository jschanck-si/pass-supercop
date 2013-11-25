/*
 * CPASSREF/ntt.c
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

#ifndef USE_FFTW
#ifndef USE_KARATSUBA
#define USE_FFTW 1
#endif
#endif

#if USE_FFTW
#include <complex.h>
#include <math.h>
#include <fftw3.h>
#endif

#include <string.h>

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "ntt.h"

static int NTT_INITIALIZED = 0;

#if USE_FFTW
static fftw_plan DFT;
static fftw_plan iDFT;

static fftw_real *dpoly = NULL;
static fftw_complex *cpoly = NULL;
static fftw_complex *nth_roots_dft = NULL;
#endif

#if USE_FFTW
int
ntt_setup() {
  int i;
  fftw_plan DFTom;

fftw_real nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
  };

  if(!NTT_INITIALIZED) {
    NTT_INITIALIZED = 1;

    if(!fftw_import_wisdom_from_filename(PASS_WISDOM)) goto error;

    dpoly = fftw_alloc_real(NTT_LEN);
    if(dpoly == NULL) goto error;

    nth_roots_dft = fftw_alloc_complex(NTT_LEN);
    if(nth_roots_dft == NULL) goto error;

    cpoly = fftw_alloc_complex(NTT_LEN);
    if(cpoly == NULL) goto error;

    DFTom = fftw_plan_dft_r2c_1d(NTT_LEN, nth_roots, nth_roots_dft,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(DFTom == NULL) goto error;

    fftw_execute(DFTom);
    fftw_destroy_plan(DFTom);

    for(i=0; i<NTT_LEN; i++)
      nth_roots_dft[i] /= NTT_LEN;

    DFT = fftw_plan_dft_r2c_1d(NTT_LEN, dpoly, cpoly,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(DFT == NULL) goto error;

    iDFT = fftw_plan_dft_c2r_1d(NTT_LEN, cpoly, dpoly,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(iDFT == NULL) goto error;
  }
  return 0;
error:
  ntt_cleanup();
  return -1;
}

int
ntt_cleanup() {
  if(NTT_INITIALIZED) {
    NTT_INITIALIZED = 0;
    fftw_destroy_plan(DFT);
    fftw_destroy_plan(iDFT);
    fftw_free(dpoly);
    fftw_free(cpoly);
    fftw_free(nth_roots_dft);
    fftw_cleanup();
  }
  return 0;
}

int
ntt(int64 *Ff, const int64 *f)
{
  int i;

  for(i=0; i<NTT_LEN; i++){
    dpoly[i] = (fftw_real) f[perm[i]];
  }

  fftw_execute(DFT); /* dpoly -> cpoly */

  for(i=0;i<(NTT_LEN/2)+1; i++){
    cpoly[i] *= nth_roots_dft[i];
  }

  fftw_execute(iDFT); /* cpoly -> dpoly */

  for(i=0; i<NTT_LEN; i++) {
    Ff[perm[NTT_LEN-i]] = f[0] + llrint(dpoly[i]);
  }

  poly_cmod(Ff);

  return 0;
}

#elif USE_KARATSUBA

int
ntt_setup() {
  NTT_INITIALIZED = 1;
  return 0;
}

int
ntt_cleanup() {
  NTT_INITIALIZED = 0;
  return 0;
}


/* Space efficient Karatsuba multiplication.
 * See: Thomé, "Karatsuba multiplication with temporary space of size \le n"
 * http://www.loria.fr/~thome/files/kara.pdf
 *
 * Note: Inputs should be of smooth length with many 2's. (i.e. 2^u*3^v)
 */
static int
karatsuba(int64 *res, int64 *tmp, const int64 *a, const int64 *b, const int64 k)
{
  /* Assumes k is even */
  int64 i;
  int64 j;
  const int64 p = k>>1;

  /* Grade school multiplication for small / odd inputs */
  if(k <= 36 || k%2 != 0) {
    memset(res, 0, 2*k*sizeof(int64));
    for(i=0; i<k; i++) {
      if(a[i] == 0) continue;
      for(j=0; j<k; j++) {
        res[i+j] += a[i]*b[j];
      }
    }

    return 0;
  }

  /* res = [[c = al - ah]/p [d = bl - bh]/p [__]/2p] */
  /* tmp = [[__]/2p] */
  for(i=0; i<p; i++){
    res[i] = a[i] - a[i+p];
    res[i+p] = b[i+p] - b[i];
  }

  /* res = [[c]/p [d]/p [__]/2p] */
  /* tmp = [[c*d]/2p] */
  karatsuba(tmp, res+k, res, res+p, p);

  /* res = [[__]/p [__]/p [h = H{a}*H{b}]/2p] */
  /* tmp = [[c*d]/2p] */
  karatsuba(res+k,res,a+p,b+p,p);

  /* res = [[__]/p [__]/p [h]/2p] */
  /* tmp = [[L{c*d} L{h}]/p [H{c*d} + H{h}]/p] */
  for(i=0; i<k; i++) {
    tmp[i] += res[k+i];
  }

  /* res = [[__]/p [L{c*d} + L{h}]/p [h]/2p] */
  /* tmp = [[L{c*d} L{h}]/p [H{c*d} + H{h}]/p] */
  memcpy(res+p,tmp,p*sizeof(int64));

  /* res = [[__]/p [L{c*d} + L{h}]/p [L{h} + H{c*d} + H{h}]/p [H{h}]/p] */
  /* tmp = [[L{c*d} L{h}]/p [H{c*d} + H{h}]/p] */
  for(i=0; i<p; i++) {
    res[k+i] += tmp[p+i];
  }

  /* res = [[__]/p [L{c*d} + L{h}]/p [L{h} + H{c*d} + H{h}]/p [H{h}]/p] */
  /* tmp = [[l = L{a}*L{b}]/2p] */
  karatsuba(tmp,res,a,b,p);

  /* res = [[L{l}]/p [L{c*d} + L{h}]/p [L{h} + H{c*d} + H{h}]/p [H{h}]/p] */
  /* tmp = [[L{l}]/p [H{l}]/p] */
  memcpy(res,tmp,p*sizeof(int64));

  /* res = [[L{l}]/p [H{l} + L{c*d} + L{h}]/p [L{h} + H{c*d} + H{h}]/p [H{h}]/p] */
  /* tmp = [[L{l}]/p [H{l}]/p] */
  for(i=0; i<p; i++) {
    res[p+i] += tmp[i] + tmp[p+i];
  }

  /* res = [[L{l}]/p [H{l} + L{l} + L{h} + L{c*d}]/p [L{h} + H{l} + H{h} + H{c*d}]/p [H{h}]/p]
         = [[L{l}]/p [H{l} + L{a}*H{b} + L{b}*H{a} + L{h}]/2p [H{h}]/p]
     tmp = [[L{L{a}*L{b}}]/p [H{L{a}*L{b}}]/p] */
  for(i=p; i<k; i++) {
    res[p+i] += tmp[i];
  }

  return 0;
}

int
ntt(int64 *Fw, const int64 *w)
{
  int64 i;
  int64 res[2*NTT_LEN];
  int64 tmp[NTT_LEN];
  int64 a[NTT_LEN];

  const int64 nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
    };

  for(i=0; i<NTT_LEN; i++){
    a[i] = w[perm[i]];
  }

  karatsuba(res, tmp, a, nth_roots, NTT_LEN);

  for(i=0; i<NTT_LEN; i++) {
    Fw[perm[NTT_LEN-i]] = cmod(w[0] + res[i] + res[i+NTT_LEN]);
  }

  return 0;
}

#else /* Not using FFTW */

int
ntt_setup() {
  NTT_INITIALIZED = 1;
  return 0;
}

int
ntt_cleanup() {
  NTT_INITIALIZED = 0;
  return 0;
}

int
ntt(int64 *Fw, const int64 *w)
{
  int64 i;
  int64 j;

int64 nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
  };

  /* Rader DFT: Length N-1 convolution of w (permuted according to
   * PASS_PERMUTATION) and the vector [g, g^2, g^3, ... g^N-1].
   *
   * TODO: Certainly faster to always store coefficients in multiplicative
   * order and just perform permutation when publishing z or extracting
   * coefficients.
   */

  for (i = 0; i < NTT_LEN; i++) {
    Fw[perm[i]] += w[0]; /* Each coefficient of Fw gets a w[0] contribution */

    if (w[perm[i]] == 0) continue;

    for (j = i; j < NTT_LEN; j++) {
      Fw[perm[NTT_LEN-j]] += (w[perm[i]] * nth_roots[j-i]);
    }

    for (j = 0; j < i; j++) {
      Fw[perm[NTT_LEN-j]] += (w[perm[i]] * nth_roots[NTT_LEN+j-i]);
    }
  }

  /* Fw[0] (evaluation of w at 1). */
  for (i = 0; i < PASS_N; i++) {
    Fw[0] += w[i];
  }

  poly_cmod(Fw);

  return 0;
}
#endif
