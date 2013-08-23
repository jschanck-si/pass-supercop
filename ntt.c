/*
 * CPASSREF/ntt.c
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

#if USE_FFTW
#include <complex.h>
#include <math.h>
#include <fftw3.h>
#endif

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "ntt.h"

static int NTT_INITIALIZED = 0;

#if USE_FFTW
static fftwl_plan DFT;
static fftwl_plan iDFT;

static fftwl_real *dpoly = NULL;
static fftwl_complex *cpoly = NULL;
static fftwl_complex *nth_roots_dft = NULL;
#endif

int
ntt_setup() {
#if USE_FFTW
  fftwl_plan DFTom;

fftwl_real nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
  };

  if(!NTT_INITIALIZED) {
    NTT_INITIALIZED = 1;

    if(!fftwl_import_wisdom_from_filename(PASS_WISDOM)) goto error;

    dpoly = fftwl_alloc_real(NTT_LEN);
    if(dpoly == NULL) goto error;

    nth_roots_dft = fftwl_alloc_complex(NTT_LEN);
    if(nth_roots_dft == NULL) goto error;

    cpoly = fftwl_alloc_complex(NTT_LEN);
    if(cpoly == NULL) goto error;

    DFTom = fftwl_plan_dft_r2c_1d(NTT_LEN, nth_roots, nth_roots_dft,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(DFTom == NULL) goto error;

    fftwl_execute(DFTom);
    fftwl_destroy_plan(DFTom);

    DFT = fftwl_plan_dft_r2c_1d(NTT_LEN, dpoly, cpoly,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(DFT == NULL) goto error;

    iDFT = fftwl_plan_dft_c2r_1d(NTT_LEN, cpoly, dpoly,
        FFTW_WISDOM_ONLY | FFTW_PATIENT);
    if(DFT == NULL) goto error;
  }
  return 0;
error:
  ntt_cleanup();
  return -1;

#else
  NTT_INITIALIZED = 1;
  return 0;
#endif
}

int
ntt_cleanup() {
#if USE_FFTW
  if(NTT_INITIALIZED) {
    NTT_INITIALIZED = 0;
    fftwl_destroy_plan(DFT);
    fftwl_destroy_plan(iDFT);
    fftwl_free(dpoly);
    fftwl_free(cpoly);
    fftwl_free(nth_roots_dft);
    fftwl_cleanup();
  }
  return 0;
#else
  NTT_INITIALIZED = 0;
  return 0;
#endif
}

#if USE_FFTW
int
ntt(int64 *Ff, const int64 *f)
{
  int i;

  for(i=0; i<NTT_LEN; i++){
    dpoly[i] = (fftwl_real) f[perm[i]];
  }

  fftwl_execute(DFT); /* dpoly -> cpoly */

  for(i=0;i<(NTT_LEN/2)+1; i++){
    cpoly[i] *= nth_roots_dft[i];
  }

  fftwl_execute(iDFT); /* cpoly -> dpoly */

  for(i=0; i<NTT_LEN; i++) {
    Ff[perm[NTT_LEN-i]] = f[0] + rintl(dpoly[i]/NTT_LEN);
  }

  poly_cmod(Ff, PASS_p);

  return 0;
}

#else

int
ntt(int64 *Fw, const int64 *w)
{
  int64 i;
  int64 j;

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

  poly_cmod(Fw, PASS_p);

  return 0;
}
#endif
