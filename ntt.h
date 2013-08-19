/* Requires:
 *    pass_types.h
 */

#ifndef CPASSREF_EVAL_H_
#define CPASSREF_EVAL_H_

#define NTT_LEN (PASS_N-1)

static const int64 perm[NTT_LEN+1] = {
#include PASS_PERMUTATION
    , 1
  };

static fftwl_real nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
  };

static const int64 S[PASS_t] = {
#include PASS_EVAL_POINTS
  };

int
ntt_setup();

int
ntt_cleanup();

int
ntt(int64 *wS, const int64 *w);

#endif
