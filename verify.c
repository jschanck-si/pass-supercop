#include <string.h>

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "hash.h"
#include "formatc.h"
#include "ntt.h"
#include "pass.h"


#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

int
verify(const unsigned char *h, const int64 *z, const int64 *pubkey,
    const unsigned char *message, const int msglen)
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

