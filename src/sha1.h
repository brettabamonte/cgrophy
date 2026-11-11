#ifndef _SHA1_H
#define _SHA1_H

#ifdef SHA1_EXPORTS
	#define SHA1_API extern __declspec(dllexport)
#else
	#define SHA1_API extern __declspec(dllimport)
#endif

#include "types.h"

/* public api */
typedef struct Sha1Ctx Sha1Ctx;

SHA1_API void sha1_init(Sha1Ctx *ctx);
SHA1_API void sha1_update(Sha1Ctx *ctx, void *ptr, size_t len);
SHA1_API void sha1_final(Sha1Ctx *ctx, u8 *digest);

#endif
