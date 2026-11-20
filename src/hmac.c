/*
 * NIST FIPS: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
 */

#include "hash.h"
#include "hmac.h"
#include "types.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined (_WIN64)
    #include <malloc.h>
#endif

#define I_PAD 0x36
#define O_PAD 0x5c

struct CgrophyHmac {
    u8              *key;
    u8              *key_ipad;
    u8              *key_opad;
    CgrophyHashFunc *hash_function;
};

/* public api */
CgrophyHmac* hmac_new(void)
{
    CgrophyHmac *new;
    new = (CgrophyHmac *)malloc(sizeof(*new));

    return new;
}

void hmac_init(CgrophyHmac *obj, u8 *key, size_t key_len, CgrophyHashFuncType type)
{
    u16 i, digest_size, block_size;
    CgrophyHashFunc *h_func;
    u8 *k_digest;
    u8 *k0;

    /* working vars */
    digest_size = hash_function_digest_size(type);
    block_size = hash_function_block_size(type);
    h_func = hash_function_factory(type);
    hash_function_init(h_func);

    /* setup hmac structure */
    //TODO (brett): implement memory allocator for sensitive bytes
    obj->key = (u8 *)malloc(sizeof(*obj->key) * block_size);
    obj->key_ipad = (u8 *)malloc(sizeof(*obj->key) * block_size);
    obj->key_opad = (u8 *)malloc(sizeof(*obj->key) * block_size);
    obj->hash_function = h_func;

    if (key_len == block_size)
    {
        memcpy(obj->key, key, block_size);
    }
    else
    {
        /* setup hash function for determining key */
        k_digest = (u8 *)malloc(sizeof(*k_digest) * digest_size);
        k0 = (u8 *)malloc(sizeof(*k0) * block_size);

        if (key_len > block_size)
        {
            /* hash input key */
            CgrophyHashFunc *kdf = hash_function_factory(type);
            hash_function_init(kdf);
            hash_function_update(kdf, key, key_len);
            hash_function_final(kdf, k_digest);
            hash_function_destroy(kdf);

            /* create B-byte key */
            memcpy(k0, k_digest, digest_size); /* copy H(K) */
            memset(k0 + digest_size, 0x00, block_size - digest_size); /* pad with zeros until block size */
        }
        else
        {
            memcpy(k0, key, key_len);
            memset(k0 + key_len, 0x00, block_size - key_len);
        }
        memcpy(obj->key, k0, block_size);
        free(k_digest);
        free(k0);
    }

    // Pre-compute k0 ^ ipad & k0 ^ opad
    for(i=0; i < block_size; i++)
    {
        obj->key_opad[i] = obj->key[i] ^ O_PAD;
        obj->key_ipad[i] = obj->key[i] ^ I_PAD;
    }

    /* start hashing */
    hash_function_update(obj->hash_function, obj->key_ipad, block_size);
}

void hmac_update(CgrophyHmac *obj, u8 *ptr, size_t len)
{
    hash_function_update(obj->hash_function, ptr, len);
}

void hmac_final(CgrophyHmac *obj, unsigned char *digest)
{
    u8 *buf;
    CgrophyHashFunc *final_hash;
    u16 digest_size, block_size;

    /* working vars */
    block_size = hash_function_block_size(obj->hash_function->type);
    digest_size = hash_function_digest_size(obj->hash_function->type);
    
    /* create new hash context */
    final_hash = hash_function_factory(obj->hash_function->type);
    hash_function_init(final_hash);

    /* buffer for output of ((K0 ⊕ ipad) || text) */
    buf = (u8 *)malloc(sizeof(*buf) * digest_size);

    hash_function_final(obj->hash_function, buf);

    hash_function_update(final_hash, obj->key_opad, block_size);
    hash_function_update(final_hash, buf, digest_size);
    hash_function_final(final_hash, digest);

    free(buf);
}

void hmac_destroy(CgrophyHmac *obj)
{
    assert(obj);
    free(obj->key);
    free(obj->key_ipad);
    free(obj->key_opad);
    hash_function_destroy(obj->hash_function);
    free(obj);
}

