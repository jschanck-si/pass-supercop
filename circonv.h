#ifndef CPASSREF_CIRCONV_H_
#define CPASSREF_CIRCONV_H_

int
circonv(int64 *c, const int64 *a, const int64 *b);

int
bsparseconv(int64 *c, const int64 *a, const b_sparse_poly *b);
#endif
