#ifndef CPASSREF_PASS_H_
#define CPASSREF_PASS_H_

static const int64 S[PASS_t] = {
#include PASS_EVAL_POINTS
  };

int
gen_key(int64 *f);

int
gen_pubkey(int64 *pkey, int64 *skey);

int
mknoise(int64 *y);

int
reject(const int64 *z);

int
sign(unsigned char *h, int64 *z, const int64 *key,
    const unsigned char *message, const int msglen);

int
verify(const unsigned char *h, const int64 *z, const int64 *pubkey,
    const unsigned char *message, const int msglen);

#endif
