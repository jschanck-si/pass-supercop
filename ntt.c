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
  if(!NTT_INITIALIZED) {
    fftwl_import_wisdom_from_filename(PASS_WISDOM);

    dpoly = (fftwl_real*) fftwl_malloc(sizeof(fftwl_real) * NTT_LEN);
    nth_roots_dft = (fftwl_complex*) fftwl_malloc(sizeof(fftwl_complex) * NTT_LEN);
    cpoly = (fftwl_complex*) fftwl_malloc(sizeof(fftwl_complex) * NTT_LEN);

    DFTom = fftwl_plan_dft_r2c_1d(NTT_LEN, nth_roots, nth_roots_dft, FFTW_ESTIMATE);
    fftwl_execute(DFTom);
    fftwl_destroy_plan(DFTom);

    DFT = fftwl_plan_dft_r2c_1d(NTT_LEN, dpoly, cpoly, FFTW_ESTIMATE);
    iDFT = fftwl_plan_dft_c2r_1d(NTT_LEN, cpoly, dpoly, FFTW_ESTIMATE);

    NTT_INITIALIZED = 1;
  }
#else
    NTT_INITIALIZED = 1;
#endif

  return 0;
}

int
ntt_cleanup() {
#if USE_FFTW
  if(NTT_INITIALIZED) {
    fftwl_destroy_plan(DFT);
    fftwl_destroy_plan(iDFT);
    fftwl_free(dpoly);
    fftwl_free(cpoly);
    fftwl_free(nth_roots_dft);
    fftwl_forget_wisdom();
    NTT_INITIALIZED = 0;
  }
#else
    NTT_INITIALIZED = 0;
#endif

  return 0;
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
