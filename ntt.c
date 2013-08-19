#include <complex.h>
#include <math.h>
#include <fftw3.h>

#include "constants.h"
#include "pass_types.h"
#include "ntt.h"

static fftwl_plan DFT;
static fftwl_plan iDFT;

static int NTT_INITIALIZED = 0;
static long double *dpoly = NULL;
static fftwl_complex *cpoly = NULL;
static fftwl_complex *com = NULL;


int
ntt_setup() {
#if USE_FFTW
  fftwl_plan DFTom;
  if(!NTT_INITIALIZED) {
    fftwl_import_wisdom_from_filename(PASS_WISDOM);

    dpoly = (long double*) fftwl_malloc(sizeof(long double) * NTT_LEN);
    com = (fftwl_complex*) fftwl_malloc(sizeof(fftwl_complex) * NTT_LEN);
    cpoly = (fftwl_complex*) fftwl_malloc(sizeof(fftwl_complex) * NTT_LEN);

    DFTom = fftwl_plan_dft_r2c_1d(NTT_LEN, dom, com, FFTW_ESTIMATE);
    fftwl_execute(DFTom);
    fftwl_destroy_plan(DFTom);

    DFT = fftwl_plan_dft_r2c_1d(NTT_LEN, dpoly, cpoly, FFTW_ESTIMATE);
    iDFT = fftwl_plan_dft_c2r_1d(NTT_LEN, cpoly, dpoly, FFTW_ESTIMATE);

    NTT_INITIALIZED = 1;
  }
#else
    NTT_INITIALIZED = 1;
#endif
}

int
ntt_cleanup() {
#if USE_FFTW
  if(NTT_INITIALIZED) {
    fftwl_destroy_plan(DFT);
    fftwl_destroy_plan(iDFT);
    fftwl_free(dpoly);
    fftwl_free(cpoly);
    fftwl_free(com);
    fftwl_forget_wisdom();
    NTT_INITIALIZED = 0;
  }
#else
    NTT_INITIALIZED = 0;
#endif
}

#if USE_FFTW
int
ntt(int64 *Ff, const int64 *f)
{
  int i;

  for(i=0; i<NTT_LEN; i++){
    dpoly[i] = (long double) f[perm[i]];
  }

  fftwl_execute(DFT); /* dpoly -> cpoly */

  for(i=0;i<(NTT_LEN/2)+1; i++){
    cpoly[i] *= com[i];
  }

  fftwl_execute(iDFT); /* cpoly -> dpoly */

  for(i=0; i<NTT_LEN; i++) {
    Ff[perm[NTT_LEN-i]] = f[0] + rintl(dpoly[i]/NTT_LEN);
  }

  poly_cmod(Ff, PASS_p);
}

#else

int
ntt(int64 *fw, const int64 *w)
{
  int64 i;
  int64 j;

  const int64 ntt[NTT_LEN] = {
#include PASS_RADER_POLY
  };

  const int64 perm[NTT_LEN+1] = {
#include PASS_PERMUTATION
    , 1
  };

  /* Rader DFT: Length N-1 convolution of w (permuted according to
   * PASS_PERMUTATION) and the vector [g, g^2, g^3, ... g^N-1].
   *
   * TODO: Certainly faster to always store coefficients in multiplicative
   * order and just perform permutation when publishing z or extracting
   * coefficients.
   */

  for (i = 0; i < NTT_LEN; i++) {
    fw[perm[i]] += w[0]; /* Each coefficient of fw gets a w[0] contribution */

    if (w[perm[i]] == 0) continue;

    for (j = i; j < NTT_LEN; j++) {
      fw[perm[NTT_LEN-j]] += (w[perm[i]] * ntt[j-i]);
    }

    for (j = 0; j < i; j++) {
      fw[perm[NTT_LEN-j]] += (w[perm[i]] * ntt[NTT_LEN+j-i]);
    }
  }

  /* fw[0] (evaluation of w at 1). */
#if EVALUATE_AT_ONE
  for (i = 0; i < PASS_N; i++) {
    fw[0] += w[i];
  }
#endif

  return 0;
}
#endif
