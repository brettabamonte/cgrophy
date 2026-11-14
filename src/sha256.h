#ifndef _SHA256_H
#define _SHA256_H

typedef struct Sha256 Sha256;

extern Sha256*  sha256_new(void);
extern void     sha256_init(Sha256 *ctx);
extern void     sha256_update(Sha256 *ctx, unsigned char *ptr, size_t len);
extern void     sha256_final(Sha256 *ctx, unsigned char *digest);
extern void     sha256_destroy(Sha256 *ctx);

#endif
