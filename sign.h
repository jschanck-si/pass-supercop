#ifndef CPASSREF_SIGN_H_
#define CPASSREF_SIGN_H_

int
mknoise(int64 *y);

int
hash(unsigned char *h, const int64 *eval, const unsigned char *message, const int msglen);

int
reject(const int64 *z);

int
sign(unsigned char *h, int64 *z, const int64 *key, const unsigned char *message, const int msglen);

int
verify(const unsigned char *h, const int64 *z, const int64 *pubkey, const unsigned char *message, const int msglen);
#endif
