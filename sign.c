#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "constants.h"
#include "pass_types.h"
#include "crypto_hash_sha512.h"
#include "formatc.h"
#include "circonv.h"
#include "ntt.h"
#include "sign.h"


#define DEBUG 0

#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

#define NUMSIG 1000

int
main(int argc, char **argv)
{

  int i;
  int count;

#if PASS_N == 13
  int64 key[PASS_N] = {0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 1, 1, -1};
#elif PASS_N == 563
  int64 key[PASS_N] = {0, -1, 1, 1, 1, 0, 1, 1, -1, 0, 1, 0, -1, 1, 0, -1, 1, 0, 1, 1, 1, 1, -1, -1, -1, 0, -1, 1, 1, -1, 0, 1, 0, 0, 0, -1, 0, 1, -1, 0, 0, 1, 1, 1, 1, 1, 0, -1, -1, 1, 1, 0, -1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 1, 1, -1, -1, 1, -1, 0, 0, 1, 0, 0, 0, -1, 1, -1, 1, 0, -1, -1, -1, 0, 1, -1, 1, 1, 1, 0, 1, -1, 1, 0, 0, 1, -1, 0, 1, 1, 1, 0, 1, 1, 1, 0, -1, -1, 1, 0, 1, -1, 0, 0, -1, 0, -1, 1, -1, 0, -1, -1, -1, 0, -1, 0, 0, 1, 1, -1, 1, -1, 0, 1, 0, -1, 0, -1, 0, -1, -1, 1, 0, -1, -1, 1, 1, 1, 0, -1, 1, 0, 0, -1, 0, -1, 1, -1, 1, 1, 1, 1, -1, 1, 0, -1, 1, 0, -1, -1, 1, 0, 0, -1, 1, -1, -1, -1, 0, -1, 0, 0, 1, 1, 1, 0, 0, 0, 0, -1, -1, 0, 1, 0, 0, 1, 1, -1, 0, -1, -1, -1, 1, 1, -1, 0, -1, -1, 1, 0, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, -1, -1, 0, 1, 0, 0, 0, 0, 0, -1, -1, 0, 1, 0, -1, -1, -1, 1, 0, -1, 0, 1, -1, -1, 1, 0, -1, -1, 1, -1, -1, -1, 1, 0, 0, 1, -1, 0, -1, 0, 1, -1, 1, -1, -1, 0, -1, 0, 1, -1, 1, -1, 1, 0, 1, 0, -1, -1, 0, 0, 1, -1, 0, 0, -1, -1, 0, -1, 0, 1, 1, 1, -1, -1, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 0, -1, -1, -1, 0, 1, 0, 1, -1, -1, 1, 1, -1, -1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, -1, -1, 1, -1, 0, 0, 1, 0, -1, 1, 0, 0, 1, -1, 0, -1, 1, -1, 0, 1, -1, 1, 1, 0, -1, 1, 1, -1, 0, 0, 1, -1, -1, 1, 0, -1, -1, -1, -1, 1, 1, 0, 1, 1, -1, 0, 0, 0, 0, 0, 1, -1, -1, 0, 0, 1, 0, -1, 0, 0, 0, 1, -1, 1, 1, 1, -1, -1, 1, 0, 1, 0, 0, 0, 0, -1, 1, 1, -1, 0, 0, -1, 1, 1, -1, -1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, -1, 1, 0, 0, 0, 0, 1, 0, 0, -1, 1, 0, 0, -1, -1, 1, 0, 1, 1, 0, 1, 1, -1, 1, -1, 1, 0, 1, 0, 0, 0, 1, -1, 1, -1, -1, -1, 0, -1, 0, 0, -1, -1, 0, -1, 0, 0, -1, 0, 0, -1, 0, 1, -1, 1, -1, 0, 1, 1, 0, 0, 1, 1, 0, -1, -1, 1, 1, 1, 0, 0, -1, -1, 0, 1, 0, 0, 0, -1, 1, -1, -1, -1, 1, 0, 1, -1, 1, -1, 0, 1, 0, 0, -1, 1, 1, 1, 1, -1, -1, 0, 1, 1, 0, -1, 0, -1, 0, -1, -1, -1, 0, 0, -1, 0, -1, -1, 1, -1, 0, 0, -1};
#elif PASS_N == 769
  int64 key[PASS_N] = {0, -1, 0, -1, 1, -1, 0, 0, 0, 0, 0, -1, -1, -1, 1, 1, -1, 1, 0, -1, -1, -1, 0, 0, 1, 0, 1, -1, 0, 0, 1, -1, 0, 0, -1, 1, 0, -1, -1, 1, -1, 1, 0, -1, -1, -1, 1, 1, 1, 0, 0, 1, 0, 0, 0, -1, 1, -1, -1, 1, 0, 1, -1, -1, 0, -1, -1, 0, 0, 0, -1, -1, -1, 1, -1, 1, 1, 1, -1, 0, 0, 0, 1, 1, 0, -1, -1, 0, -1, 0, -1, 1, -1, 0, -1, 1, -1, -1, 0, 1, 0, 0, -1, 1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, -1, -1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, -1, 0, -1, 0, -1, 1, 1, 1, -1, -1, 1, 1, 0, -1, 0, -1, 0, -1, -1, -1, -1, 1, 0, -1, 1, 1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 0, 0, 1, 0, 1, 0, -1, -1, -1, 0, 1, -1, 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0, 1, 0, -1, 1, -1, 0, 1, 0, -1, 1, -1, 0, 0, 0, 0, -1, 0, -1, -1, 0, 1, -1, 1, 0, -1, 0, 1, -1, 1, 1, -1, 1, -1, 0, 0, -1, -1, -1, 1, 0, -1, 0, 0, 1, 0, -1, 1, -1, 1, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, -1, -1, 1, -1, 1, -1, -1, 0, -1, 1, 1, -1, 1, -1, 0, 1, 0, 0, 1, -1, 0, -1, 1, 1, -1, 1, -1, 0, 1, -1, 1, -1, -1, 1, 1, 0, 1, 1, -1, -1, -1, -1, 1, 0, -1, 0, 0, 0, 0, -1, -1, 0, 0, -1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, -1, 0, 1, 1, 0, -1, -1, -1, -1, 1, 1, -1, 0, -1, -1, 1, 1, 0, 1, -1, -1, 0, 0, 1, 0, 1, 0, 1, -1, -1, -1, -1, -1, 0, 1, -1, 0, 1, 1, -1, 1, 1, 0, 1, 1, -1, -1, 1, 0, 1, -1, -1, 1, -1, -1, 1, -1, -1, 1, 0, 1, 1, -1, -1, 1, 0, 1, -1, 1, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, -1, -1, 0, -1, 0, -1, 0, -1, -1, -1, 1, 1, 1, -1, 0, 1, 0, 0, 0, 1, 1, 1, -1, -1, 0, -1, 0, 1, 0, 0, 1, -1, -1, -1, 1, 1, 0, 0, 1, 0, -1, -1, -1, 1, 0, 1, 0, -1, 1, -1, -1, 0, -1, 0, -1, 1, -1, -1, 0, -1, 1, -1, 0, 1, -1, 1, 1, 0, 0, -1, 1, -1, -1, 0, 1, 0, 0, -1, 0, 0, 1, 0, 1, 0, 0, -1, -1, 0, 1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 0, 0, 0, -1, 0, 1, -1, -1, 0, -1, 0, 0, 0, 0, 0, -1, -1, 1, 1, 1, -1, -1, 0, 0, 1, 0, 1, -1, 1, 0, -1, 1, 0, 0, 0, 1, 1, -1, 0, -1, -1, 1, -1, -1, -1, 0, -1, -1, 0, -1, 0, -1, 0, 0, 1, 0, 1, 1, 0, -1, 1, 0, -1, -1, -1, -1, -1, 1, 0, -1, -1, 1, -1, 0, 1, 1, 0, 0, 0, 1, 0, -1, 0, 0, -1, 1, -1, 0, 1, 0, 1, 0, -1, -1, -1, 0, 0, 0, -1, 0, 0, -1, -1, 0, -1, 0, 1, 1, 1, -1, 0, 0, 0, 0, 0, -1, 0, 0, -1, -1, 0, 0, 0, -1, 1, 0, 1, -1, -1, 1, 1, -1, -1, -1, 0, -1, 1, 1, 1, -1, 1, 0, -1, -1, -1, -1, -1, 1, 0, -1, -1, 1, 1, 1, -1, -1, 1, 0, 1, 1, 0, 1, -1, -1, 1, -1, 0, 1, -1, 0, 1, 1, 1, 1, -1, -1, 0, -1, 1, -1, -1, 0, -1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, -1, 1, -1, 0, -1, 0, 1, -1, 0, 0, 1, -1, 0, 0, 0, -1, 1, 0, 0, 0, 1, -1, -1, 1, 1, 1, -1, 1, -1, 0, 0, 0, 1, 0, 1, 1, 1, 0, -1, -1, 1, 0, 0, -1, 0, -1, 0, 0, 1, 0, -1, -1, 0, 1, 1, 0, 1, 0, 1, -1, 0, 1, 1, 0, -1, 0, 1, 1, -1, 0, 1, -1, -1, -1, -1, 0, 1, 0};
#endif

  int64 keyhat[PASS_N] = {0};
  int64 pubkey[PASS_N] = {0};

  int64 *z = malloc(sizeof(int64) * PASS_N);

  unsigned char in[10] = "0000000000";
  unsigned char h[crypto_hash_sha512_BYTES];

  ntt_setup();

  ntt(keyhat, key);
  poly_cmod(keyhat, PASS_p);
  for(i=0; i<PASS_t; i++)
      pubkey[points[i]] = keyhat[points[i]];

  clock_t c0,c1;
  c0 = clock();

  count = 0;
  for(i=0; i<NUMSIG; i++) {
   //snprintf(in, sizeof(int), "%u", rand());
   count += sign(h, z, key, in, 10);
   printf("%d", (verify(h, z, pubkey, in, 10) == VALID), count);
   fflush(stdout);
  }
  printf("\n");

  c1 = clock();
  printf("Average attempt: %f\n",  (((float)count)/NUMSIG));
  printf("Time: %fs\n", (float) (c1 - c0)/(CLOCKS_PER_SEC));

#if DEBUG
  printf("\n\nKey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) key[i]));

  printf("\n\nPubkey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) pubkey[i]));
  printf("\n");

  printf("\n\nz: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) z[i]));
  printf("\n");
#endif

/*
  if(verify(h, z, pubkey, in, 10) == VALID)
      printf("\n\nOK!\n\n");
  else
      printf("\n\nBad Sig!\n\n");

  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) z[i]));
  printf("\n");
*/

  ntt_cleanup();
  return 0;
}

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


int
mknoise(int64 *y)
{
  int i;
  for(i=0; i<PASS_N; i++)
    y[i] = (rand() % (2*PASS_k + 1)) - PASS_k;

  return 0;
}

int
hash(unsigned char *h, const int64 *eval, const unsigned char *message, const int msglen)
{
  int i;
  int doclen = PASS_t * sizeof(int64) + msglen + 1;
  unsigned char *in = calloc(doclen, sizeof(unsigned char));

  //  printf("\n\nEval = [");
  //for(i=0; i<PASS_t; i++) {
  //    printf("%lld, ", eval[points[i]]);
  //}

  for(i=0; i<PASS_t; i++) {
    //snprintf(&(in[i*sizeof(int64)]), sizeof(int64), "%lld", (long long int) eval[points[i]]);
    in[i*sizeof(int64)] = eval[points[i]];
  }

  strncpy(&(in[PASS_t * sizeof(int64)]), message, msglen);

  crypto_hash_sha512(h, in, doclen);

  free(in);
  return 0;
}

int
reject(const int64 *z)
{
  int i;

  /* TODO: make this constant time */
  for(i=0; i<PASS_N; i++) {
    if(abs(z[i]) > (PASS_k - PASS_b))
      return 1;
  }

  return 0;
}

int
sign(unsigned char *h, int64 *z, const int64 *key, const unsigned char *message, const int msglen)
{
  int count;
  b_sparse_poly c;
  int64 y[PASS_N] = {0};
  int64 Fy[PASS_N] = {0};

  count = 0;
  do {
    CLEAR(Fy);

    mknoise(y);
    ntt(Fy, y);
    hash(h, Fy, message, msglen);
    formatc(&c, h);

    /* z = y += f*c */
    bsparseconv(y, key, &c);
    /* No modular reduction required. */

    count++;
  } while (reject(y));

#if DEBUG
  int i;
  printf("\n\ny: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) y[i]));
  printf("\n");

  printf("\n\nc: ");
  for(i=0; i<PASS_b; i++)
    printf("(%lld, %lld) ", c.ind[i], c.val[i]);
  printf("\n");
#endif

  memcpy(z, y, PASS_N*sizeof(int64));

  return count;
}

int
verify(const unsigned char *h, const int64 *z, const int64 *pubkey, const unsigned char *message, const int msglen)
{
  int i;
  b_sparse_poly c;
  int64 rawc[PASS_N] = {0};
  int64 Fc[PASS_N] = {0};
  int64 Fz[PASS_N] = {0};
  unsigned char h2[crypto_hash_sha512_BYTES] = {0};

  //printf("ENTERED VERIFY\n");

  if(reject(z))
    return INVALID;

  //printf("IN RANGE\n");
  formatc(&c, h);
  for(i=0; i<PASS_b; i++)
    rawc[c.ind[i]] = c.val[i];

//printf("\n\n c = [");
//for(i=0; i<PASS_N; i++) {
//  printf("%d, ", rawc[i]);
//}
//printf("\n");
//
//printf("\n\n pubkey = [");
//for(i=0; i<PASS_N; i++) {
//  printf("%d, ", pubkey[i]);
//}
//printf("\n");

  ntt(Fc, rawc);
//printf("\n\n Fc = [");
//for(i=0; i<PASS_N; i++) {
//  printf("%d, ", Fc[i]);
//}
//printf("\n");

  ntt(Fz, z);
  for(i=0; i<PASS_N; i++) {
    Fz[i] -= Fc[i] * pubkey[i];
  }

  poly_cmod(Fz, PASS_p);

  hash(h2, Fz, message, msglen);

  /* TODO: Make this a constant time compare */
  for(i=0; i<crypto_hash_sha512_BYTES; i++) {
    if(h2[i] != h[i])
      return INVALID;
  }

  return VALID;
}
