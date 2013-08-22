#ifndef CPASSREF_HASH_H_
#define CPASSREF_HASH_H_

#include "crypto_hash_sha512.h"

#define HASH_BYTES 64

int
hash(unsigned char *h, const int64 *eval, const unsigned char *msg_digest);

#endif
