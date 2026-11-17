#ifndef _HMAC_H
#define _HMAC_H

#include "types.h"

typedef struct CgrophyHmac CgrophyHmac;

extern CgrophyHmac* hmac_new(void);
extern void hmac_init(CgrophyHmac *obj, u8 *key, size_t key_len, CgrophyHashFunc *hash_function);
extern void hmac_update(CgrophyHmac *obj, unsigned char *ptr, size_t len);
extern void hmac_final(CgrophyHmac *obj, unsigned char *digest);
extern void hmac_destroy(CgrophyHmac *obj);

#endif
