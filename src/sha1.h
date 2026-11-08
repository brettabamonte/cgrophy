#ifndef _SHA1_H
#define _SHA1_H

#include "types.h"

/* public api */
typedef struct Sha1Ctx Sha1Ctx;

extern void sha1_init(Sha1Ctx *ctx);
extern void sha1_update(Sha1Ctx *ctx, void *ptr, size_t len);
extern void sha1_final(Sha1Ctx *ctx, u8 *digest);

#endif
