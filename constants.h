#ifndef CPASSREF_CONST_H_
#define CPASSREF_CONST_H_

/* Default compile time optioms */
#ifndef USE_FFTW
#define USE_FFTW 1
#endif

#ifndef VERIFY
#define VERIFY 1
#endif

#ifndef DEBUG
#define DEBUG 0
#endif


/* Return values for verify */
#define VALID 0
#define INVALID 1


/* Parameters */
#define PASS_N 769

#define HASH_BYTES 64
#define SAFE_RAND_N (65536 - (65536 % PASS_N))
#define SAFE_RAND_k (65536 - (65536 % (2 * PASS_k + 1)))


#if PASS_N == 13
#define PASS_p 53
#define PASS_g 16
#define PASS_k 31
#define PASS_b 2
#define PASS_t 6
#define PASS_RADER_POLY "data/13_rader.dat"
#define PASS_PERMUTATION "data/13_perm.dat"
#define PASS_EVAL_POINTS "data/13_points.dat"
#define PASS_WISDOM "data/12_wisdom.dat"
#endif



#if PASS_N == 563
#define PASS_p 429007
#define PASS_g 17693
#define PASS_k 16383
#define PASS_b 24
#define PASS_t 274
#define PASS_RADER_POLY "data/563_rader.dat"
#define PASS_PERMUTATION "data/563_perm.dat"
#define PASS_EVAL_POINTS "data/563_points.dat"
#define PASS_WISDOM "data/562_wisdom.dat"
#endif



#if PASS_N == 769
#define PASS_p 862819
#define PASS_g 754192
#define PASS_k 32767
#define PASS_b 29
#define PASS_t 400
#define PASS_RADER_POLY "data/769_rader.dat"
#define PASS_PERMUTATION "data/769_perm.dat"
#define PASS_EVAL_POINTS "data/769_points.dat"
#define PASS_WISDOM "data/768_wisdom.dat"
#endif



/* Limit required by mknoise in sign.c */
#if PASS_k >= 32768
#error "Parameter k too large."
#endif

/* Limit required by formatc */
#if PASS_b >= 64
#error "Parameter b too large."
#endif

#endif
