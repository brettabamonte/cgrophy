#ifndef _SHA256_H
#define _SHA256_H

/* public api */
typedef struct Sha256Ctx Sha256Ctx;

extern Sha256Ctx *sha256_new(void);
extern void sha256_init(Sha256Ctx *ctx);
extern void sha256_update(Sha256Ctx *ctx, unsigned char *ptr, size_t len);
extern void sha256_final(Sha256Ctx *ctx, unsigned char *digest);
extern void sha256_destroy(Sha256Ctx *ctx);

#endif
