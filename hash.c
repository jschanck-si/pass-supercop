#include <string.h>

#include "constants.h"
#include "pass_types.h"
#include "hash.h"
#include "pass.h"

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
