#ifndef _SHA1_H
#define _SHA1_H

/* public api */
typedef struct Sha1Ctx Sha1Ctx;

extern Sha1Ctx *sha1_new(void); /* creates object on heap & initalizes */
extern void sha1_init(Sha1Ctx *ctx);
extern void sha1_update(Sha1Ctx *ctx, void *ptr, size_t len);
extern void sha1_final(Sha1Ctx *ctx, unsigned char *digest);
extern void sha1_destroy(Sha1Ctx *ctx);

#endif
