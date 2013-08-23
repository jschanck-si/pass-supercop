/*
 * CPASSREF/constants.h
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
#define INVALID (-1)


/* Parameters */
#define PASS_N 769

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
#define PASS_WISDOM "data/562_wisdom_single.dat"
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
#define PASS_WISDOM "data/768_wisdom_single.dat"
#endif



#if (PASS_k) & (PASS_k + 1)
#error "Parameter k should be one less than a power of two"
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
