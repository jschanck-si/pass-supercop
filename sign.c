#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "crypto_hash_sha512.h"
#include "formatc.h"
#include "circonv.h"
#include "ntt.h"
#include "sign.h"


#define TRIALS 10000

#define MLEN 48

#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

int
main(int argc, char **argv)
{
  int i;
  int count;

  time_t seed = time(NULL);
  printf("Generating %d signatures %s\n", TRIALS,
          VERIFY ? "and verifying" : "and not verifying");

  printf("seed: %ld\n\n", seed);
  srand(seed);

#if PASS_N == 13
  int64 key[PASS_N] = {0, -1, 0, -1, -1, -1, -1, -1, 0, 0, 1, 1, -1};
#elif PASS_N == 563
  int64 key[PASS_N] = {0, -1, 1, 1, 1, 0, 1, 1, -1, 0, 1, 0, -1, 1, 0, -1, 1,
    0, 1, 1, 1, 1, -1, -1, -1, 0, -1, 1, 1, -1, 0, 1, 0, 0, 0, -1, 0, 1, -1, 0,
    0, 1, 1, 1, 1, 1, 0, -1, -1, 1, 1, 0, -1, -1, 0, 1, 0, -1, 0, 0, 0, 1, 1,
    1, -1, -1, 1, -1, 0, 0, 1, 0, 0, 0, -1, 1, -1, 1, 0, -1, -1, -1, 0, 1, -1,
    1, 1, 1, 0, 1, -1, 1, 0, 0, 1, -1, 0, 1, 1, 1, 0, 1, 1, 1, 0, -1, -1, 1, 0,
    1, -1, 0, 0, -1, 0, -1, 1, -1, 0, -1, -1, -1, 0, -1, 0, 0, 1, 1, -1, 1, -1,
    0, 1, 0, -1, 0, -1, 0, -1, -1, 1, 0, -1, -1, 1, 1, 1, 0, -1, 1, 0, 0, -1,
    0, -1, 1, -1, 1, 1, 1, 1, -1, 1, 0, -1, 1, 0, -1, -1, 1, 0, 0, -1, 1, -1,
    -1, -1, 0, -1, 0, 0, 1, 1, 1, 0, 0, 0, 0, -1, -1, 0, 1, 0, 0, 1, 1, -1, 0,
    -1, -1, -1, 1, 1, -1, 0, -1, -1, 1, 0, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, -1,
    -1, 0, 1, 0, 0, 0, 0, 0, -1, -1, 0, 1, 0, -1, -1, -1, 1, 0, -1, 0, 1, -1,
    -1, 1, 0, -1, -1, 1, -1, -1, -1, 1, 0, 0, 1, -1, 0, -1, 0, 1, -1, 1, -1,
    -1, 0, -1, 0, 1, -1, 1, -1, 1, 0, 1, 0, -1, -1, 0, 0, 1, -1, 0, 0, -1, -1,
    0, -1, 0, 1, 1, 1, -1, -1, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 1, 0, -1, 0, 0,
    0, 1, 0, -1, -1, -1, 0, 1, 0, 1, -1, -1, 1, 1, -1, -1, 1, 1, 0, 0, 1, 1, 0,
    0, 1, 0, 0, 1, 1, 0, -1, -1, 1, -1, 0, 0, 1, 0, -1, 1, 0, 0, 1, -1, 0, -1,
    1, -1, 0, 1, -1, 1, 1, 0, -1, 1, 1, -1, 0, 0, 1, -1, -1, 1, 0, -1, -1, -1,
    -1, 1, 1, 0, 1, 1, -1, 0, 0, 0, 0, 0, 1, -1, -1, 0, 0, 1, 0, -1, 0, 0, 0,
    1, -1, 1, 1, 1, -1, -1, 1, 0, 1, 0, 0, 0, 0, -1, 1, 1, -1, 0, 0, -1, 1, 1,
    -1, -1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, -1, 1, 0, 0, 0,
    0, 1, 0, 0, -1, 1, 0, 0, -1, -1, 1, 0, 1, 1, 0, 1, 1, -1, 1, -1, 1, 0, 1,
    0, 0, 0, 1, -1, 1, -1, -1, -1, 0, -1, 0, 0, -1, -1, 0, -1, 0, 0, -1, 0, 0,
    -1, 0, 1, -1, 1, -1, 0, 1, 1, 0, 0, 1, 1, 0, -1, -1, 1, 1, 1, 0, 0, -1, -1,
    0, 1, 0, 0, 0, -1, 1, -1, -1, -1, 1, 0, 1, -1, 1, -1, 0, 1, 0, 0, -1, 1, 1,
    1, 1, -1, -1, 0, 1, 1, 0, -1, 0, -1, 0, -1, -1, -1, 0, 0, -1, 0, -1, -1, 1,
    -1, 0, 0, -1};
#elif PASS_N == 769
  int64 key[PASS_N] = {0, -1, 0, -1, 1, -1, 0, 0, 0, 0, 0, -1, -1, -1, 1, 1,
    -1, 1, 0, -1, -1, -1, 0, 0, 1, 0, 1, -1, 0, 0, 1, -1, 0, 0, -1, 1, 0, -1,
    -1, 1, -1, 1, 0, -1, -1, -1, 1, 1, 1, 0, 0, 1, 0, 0, 0, -1, 1, -1, -1, 1,
    0, 1, -1, -1, 0, -1, -1, 0, 0, 0, -1, -1, -1, 1, -1, 1, 1, 1, -1, 0, 0, 0,
    1, 1, 0, -1, -1, 0, -1, 0, -1, 1, -1, 0, -1, 1, -1, -1, 0, 1, 0, 0, -1, 1,
    0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, -1, -1, 1, 1, 1, 0, 1, 1, 0,
    1, 0, 0, 1, 0, -1, 0, -1, 0, -1, 1, 1, 1, -1, -1, 1, 1, 0, -1, 0, -1, 0,
    -1, -1, -1, -1, 1, 0, -1, 1, 1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 0, 0, 1, 0,
    1, 0, -1, -1, -1, 0, 1, -1, 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0, 1, 0,
    -1, 1, -1, 0, 1, 0, -1, 1, -1, 0, 0, 0, 0, -1, 0, -1, -1, 0, 1, -1, 1, 0,
    -1, 0, 1, -1, 1, 1, -1, 1, -1, 0, 0, -1, -1, -1, 1, 0, -1, 0, 0, 1, 0, -1,
    1, -1, 1, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, -1, -1, 1, -1, 1, -1, -1, 0, -1,
    1, 1, -1, 1, -1, 0, 1, 0, 0, 1, -1, 0, -1, 1, 1, -1, 1, -1, 0, 1, -1, 1,
    -1, -1, 1, 1, 0, 1, 1, -1, -1, -1, -1, 1, 0, -1, 0, 0, 0, 0, -1, -1, 0, 0,
    -1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, -1, 0, 1, 1, 0, -1, -1, -1, -1, 1, 1, -1,
    0, -1, -1, 1, 1, 0, 1, -1, -1, 0, 0, 1, 0, 1, 0, 1, -1, -1, -1, -1, -1, 0,
    1, -1, 0, 1, 1, -1, 1, 1, 0, 1, 1, -1, -1, 1, 0, 1, -1, -1, 1, -1, -1, 1,
    -1, -1, 1, 0, 1, 1, -1, -1, 1, 0, 1, -1, 1, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0,
    1, -1, -1, 0, -1, 0, -1, 0, -1, -1, -1, 1, 1, 1, -1, 0, 1, 0, 0, 0, 1, 1,
    1, -1, -1, 0, -1, 0, 1, 0, 0, 1, -1, -1, -1, 1, 1, 0, 0, 1, 0, -1, -1, -1,
    1, 0, 1, 0, -1, 1, -1, -1, 0, -1, 0, -1, 1, -1, -1, 0, -1, 1, -1, 0, 1, -1,
    1, 1, 0, 0, -1, 1, -1, -1, 0, 1, 0, 0, -1, 0, 0, 1, 0, 1, 0, 0, -1, -1, 0,
    1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 0, 0, 0, -1, 0, 1, -1, -1, 0, -1, 0, 0,
    0, 0, 0, -1, -1, 1, 1, 1, -1, -1, 0, 0, 1, 0, 1, -1, 1, 0, -1, 1, 0, 0, 0,
    1, 1, -1, 0, -1, -1, 1, -1, -1, -1, 0, -1, -1, 0, -1, 0, -1, 0, 0, 1, 0, 1,
    1, 0, -1, 1, 0, -1, -1, -1, -1, -1, 1, 0, -1, -1, 1, -1, 0, 1, 1, 0, 0, 0,
    1, 0, -1, 0, 0, -1, 1, -1, 0, 1, 0, 1, 0, -1, -1, -1, 0, 0, 0, -1, 0, 0,
    -1, -1, 0, -1, 0, 1, 1, 1, -1, 0, 0, 0, 0, 0, -1, 0, 0, -1, -1, 0, 0, 0,
    -1, 1, 0, 1, -1, -1, 1, 1, -1, -1, -1, 0, -1, 1, 1, 1, -1, 1, 0, -1, -1,
    -1, -1, -1, 1, 0, -1, -1, 1, 1, 1, -1, -1, 1, 0, 1, 1, 0, 1, -1, -1, 1, -1,
    0, 1, -1, 0, 1, 1, 1, 1, -1, -1, 0, -1, 1, -1, -1, 0, -1, 0, 0, 1, 0, 0, 0,
    1, 0, 1, 0, 0, 1, 0, 1, 0, -1, 1, -1, 0, -1, 0, 1, -1, 0, 0, 1, -1, 0, 0,
    0, -1, 1, 0, 0, 0, 1, -1, -1, 1, 1, 1, -1, 1, -1, 0, 0, 0, 1, 0, 1, 1, 1,
    0, -1, -1, 1, 0, 0, -1, 0, -1, 0, 0, 1, 0, -1, -1, 0, 1, 1, 0, 1, 0, 1, -1,
    0, 1, 1, 0, -1, 0, 1, 1, -1, 0, 1, -1, -1, -1, -1, 0, 1, 0};
#endif

  int64 *z;
  unsigned char in[MLEN] = "000000000000000000000000000000000000000000000000";
  unsigned char h[HASH_BYTES];

  z = malloc(PASS_N * sizeof(int64));
  ntt_setup();

#if VERIFY
  int nbver = 0;

  int64 Ff[PASS_N] = {0};
  int64 pubkey[PASS_N] = {0};
  ntt(Ff, key);
  poly_cmod(Ff, PASS_p);
  for(i=0; i<PASS_t; i++)
      pubkey[S[i]] = Ff[S[i]];
#endif

  clock_t c0,c1;
  c0 = clock();

  count = 0;
  for(i=0; i<TRIALS; i++) {
   snprintf((char *)in, sizeof(long int), "%ld", lrand48());
   count += sign(h, z, key, in, MLEN);
#if VERIFY
   nbver += (VALID == verify(h, z, pubkey, in, MLEN));
#endif
  }
  printf("\n");

  c1 = clock();
  printf("Total attempts: %d\n",  count);
#if VERIFY
  printf("Valid signatures: %d/%d\n",  nbver, TRIALS);
#endif
  printf("Attempts/sig: %f\n",  (((float)count)/TRIALS));
  printf("Time/sig: %fs\n", (float) (c1 - c0)/(TRIALS*CLOCKS_PER_SEC));

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
  int i = 0;
  int x;
  while(i < PASS_N) {
    x = rand() & (2*PASS_k + 1); // Should be power of 2 - 1...

    if(x == SAFE_RAND_k) continue;

    y[i] = x - PASS_k;
    i++;
  }

  return 0;
}


int
hash(unsigned char *h, const int64 *y, const unsigned char *msg_digest)
{
  int i;
  unsigned char in[PASS_t + HASH_BYTES];
  unsigned char *pos = in + HASH_BYTES;

  strncpy((char *)in, (const char *)msg_digest, HASH_BYTES);

  for(i=0; i<PASS_t; i++) {
    *pos = (unsigned char) (y[S[i]] & 0xff);
    pos++;
  }

  crypto_hash_sha512(h, in, PASS_t + HASH_BYTES);

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
  int64 y[PASS_N];
  int64 Fy[PASS_N];
  unsigned char msg_digest[HASH_BYTES];

  crypto_hash_sha512(msg_digest, message, msglen);

  count = 0;
  do {
    CLEAR(Fy);

    mknoise(y);
    ntt(Fy, y);
    hash(h, Fy, msg_digest);

    CLEAR(c.val);
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

  printf("\n\nFy: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) Fy[i]));
  printf("\n");

  printf("\n\nc: ");
  for(i=0; i<PASS_b; i++)
    printf("(%lld, %lld) ", (long long int) c.ind[i], (long long int) c.val[c.ind[i]]);
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
  int64 Fc[PASS_N] = {0};
  int64 Fz[PASS_N] = {0};
  unsigned char msg_digest[HASH_BYTES];
  unsigned char h2[HASH_BYTES];

  if(reject(z))
    return INVALID;

  CLEAR(c.val);
  formatc(&c, h);

  ntt(Fc, c.val);
  ntt(Fz, z);

  for(i=0; i<PASS_N; i++) {
    Fz[i] -= Fc[i] * pubkey[i];
  }

  poly_cmod(Fz, PASS_p);

  crypto_hash_sha512(msg_digest, message, msglen);
  hash(h2, Fz, msg_digest);

  for(i=0; i<HASH_BYTES; i++) {
    if(h2[i] != h[i])
      return INVALID;
  }

  return VALID;
}
