#include <stdlib.h>
#include <string.h>

#include "crypto_hash_sha512.h"
#include "constants.h"
#include "pass_types.h"
#include "formatc.h"

/* TODO: Standardize a format function */

int
formatc(b_sparse_poly *c, const unsigned char *digest)
{
  int i;
  int j;
  uint64 v;
  unsigned int indx;
  unsigned char pool[HASH_BYTES];
  unsigned char hash_state[HASH_BYTES];

  memcpy(pool, digest, HASH_BYTES);

/*XXX: Maximum b = 64 */
  v =  pool[0]; v <<= 8;
  v |= pool[1]; v <<= 8;
  v |= pool[2]; v <<= 8;
  v |= pool[3]; v <<= 8;
  v |= pool[4]; v <<= 8;
  v |= pool[5]; v <<= 8;
  v |= pool[6]; v <<= 8;
  v |= pool[7];

  i=0;
  j = 8;
  while(i < PASS_b){
    if(j >= (HASH_BYTES - 1)) {
      j = 0;
      memcpy(hash_state, pool, HASH_BYTES);
      crypto_hash_sha512(pool, hash_state, HASH_BYTES);
      continue;
    }

    indx = ((pool[j] << 8) | (pool[j+1]));
    j += 2;

    if(indx > SAFE_RAND_N) continue;

    indx %= PASS_N;

    if(c->val[indx] != 0) continue;

    c->ind[i] = indx;
    c->val[indx] = 2 * (v & 0x01) - 1;
    v >>= 1;
    i++;
  }

  return 0;
}
