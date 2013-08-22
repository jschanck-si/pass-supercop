#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "constants.h"
#include "pass_types.h"
#include "hash.h"
#include "ntt.h"
#include "pass.h"

#define TRIALS 10000

#define MLEN 48

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

  int64 key[PASS_N];
  int64 *z;
  unsigned char in[MLEN];
  unsigned char h[HASH_BYTES];

  memset(in, '0', MLEN);

  z = malloc(PASS_N * sizeof(int64));
  ntt_setup();

  gen_key(key);

#if DEBUG
  printf("sha512(key): ");
  crypto_hash_sha512(h, (unsigned char*)key, sizeof(int64)*PASS_N);
  for(i=0; i<HASH_BYTES; i++) {
    printf("%.2x", h[i]);
  }
  printf("\n");
#endif

#if VERIFY
  int nbver = 0;

  int64 pubkey[PASS_N] = {0};
  gen_pubkey(pubkey, key);
#endif

  clock_t c0,c1;
  c0 = clock();

  count = 0;
  for(i=0; i<TRIALS; i++) {
   snprintf((char *)in, sizeof(long int), "%d", rand());
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

