/*
 * NIST FIPS: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
 */

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

//TODO (brett): different way to specify hash function?
// relying on pointer is problematic
void hmac_init(CgrophyHmac *obj, u8 *key, size_t key_len, CgrophyHashFunc *hash_function)
{
    u16 i, digest_size, block_size;
    CgrophyHashFunc *h_func;
    u8 *k_digest;
    u8 *k0;

    /* working vars */
    obj->hash_function = hash_function; /* holding ref to input causes a use-after-free potentially based on lifetime of hash_function ptr */
    digest_size = obj->hash_function->digest_size;
    block_size = obj->hash_function->block_size;

    /* setup hmac structure */
    obj->key = (u8 *)malloc(sizeof(*obj->key) * block_size);
    obj->key_ipad = (u8 *)malloc(sizeof(*obj->key) * block_size);
    obj->key_opad = (u8 *)malloc(sizeof(*obj->key) * block_size);

    /* setup hash function for determining key */
    h_func = hash_function->new();
    k_digest = (u8 *)malloc(sizeof(*k_digest) * digest_size);
    k0 = (u8 *)malloc(sizeof(*k0) * digest_size);

    if (key_len == block_size)
    {
        memcpy(obj->key, key, block_size);
    }
    else
    {
        if (key_len > digest_size)
        {
            /* hash input key */
            h_func->update(h_func, key, key_len);
            h_func->final(h_func, k_digest);

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
    }

    // Pre-compute k0 ^ ipad & k0 ^ opad
    for(i=0; i < block_size; i++)
    {
        obj->key_opad[i] = obj->key[i] ^ O_PAD;
        obj->key_ipad[i] = obj->key[i] ^ I_PAD;
    }

    free(k_digest);
    free(k0);
}

void hmac_update(CgrophyHmac *obj, u8 *ptr, size_t len)
{
    obj->hash_function->update(obj->hash_function, obj->key_ipad, obj->hash_function->block_size);
    obj->hash_function->update(obj->hash_function, ptr, len);
}

void hmac_final(CgrophyHmac *obj, unsigned char *digest)
{
    u8 *buf;
    CgrophyHashFunc *final_hash;

    final_hash = obj->hash_function->new();
    /* buffer for output of ((K0 ⊕ ipad) || text) */
    buf = (u8 *)malloc(sizeof(*buf) * obj->hash_function->digest_size);

    obj->hash_function->final(obj->hash_function, buf);

    /* create new hash context */

    final_hash->update(final_hash, obj->key_opad, obj->hash_function->block_size);
    final_hash->update(final_hash, buf, obj->hash_function->digest_size);
    final_hash->final(final_hash, digest);

    free(buf);
}

void hmac_destroy(CgrophyHmac *obj)
{
    assert(obj);
    free(obj);
}


#ifdef HMAC_TEST

#include "sha256.h"

int main(int argc, char **argv)
{
    /* test 1. key='0xFFFF', msg='abc', hash func='sha 256' */
    Sha256Ctx *ctx_1;
    CgrophyHmac *hmac_1;
    const u8 data[34] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6F, 0x72,  0x20, 0x6B, 0x65, 0x79,  0x6C, 0x65, 0x6E, 0x3D,  0x62, 0x6C, 0x6F, 0x63,  0x6B, 0x6C, 0x65, 0x6E };
    const u8 key[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F,  0x20, 0x21, 0x22, 0x23,  0x24, 0x25, 0x26, 0x27,  0x28, 0x29, 0x2A, 0x2B,  0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,  };
    u8 digest_1[32];
    const u8 expected_1[32] = { 0x8B, 0xB9, 0xA1, 0xDB,  0x98, 0x06, 0xF2, 0x0D,  0xF7, 0xF7, 0x7B, 0x82,  0x13, 0x8C, 0x79, 0x14,  0xD1, 0x74, 0xD5, 0x9E,  0x13, 0xDC, 0x4D, 0x01,  0x69, 0xC9, 0x05, 0x7B,  0x13, 0x3E, 0x1D, 0x62,  };
    ctx_1 = sha256_new();
    hmac_1 = hmac_new();
    hmac_init(hmac_1, key, 64, ctx_1);

    hmac_update(hmac_1, data, 34);
    hmac_final(hmac_1, digest_1);

    assert(memcmp(digest_1, expected_1, 32) == 0);
}

#endif
