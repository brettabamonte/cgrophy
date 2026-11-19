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

    /* setup hash function for determining key */
    k_digest = (u8 *)malloc(sizeof(*k_digest) * digest_size);
    k0 = (u8 *)malloc(sizeof(*k0) * digest_size);

    if (key_len == block_size)
    {
        memcpy(obj->key, key, block_size);
    }
    else
    {
        if (key_len > block_size)
        {
            /* hash input key */
            hash_function_update(h_func, key, key_len);
            hash_function_final(h_func, k_digest);

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

    /* start hashing */
    hash_function_update(obj->hash_function, obj->key_ipad, block_size);

    free(k_digest);
    free(k0);
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


#ifdef HMAC_TEST

#define TEST_CNT 2

int main(int argc, char **argv)
{
    (void)(argc);
    (void)(argv);

    int i, test_idx, pass, fail;
    pass = fail = test_idx = 0;

    printf("\033[38;5;3mHMAC Test Suite\033[0m\n\n");

    printf("\033[38;5;3mHMAC SHA-256\033[0m\n");

    /* test 1. msg='Sample message for keylen=blocklen', hash func='sha 256' */
    CgrophyHmac *hmac_1;
    int res_1;
    const u8 data[34] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6F, 0x72,  0x20, 0x6B, 0x65, 0x79,  0x6C, 0x65, 0x6E, 0x3D,  0x62, 0x6C, 0x6F, 0x63,  0x6B, 0x6C, 0x65, 0x6E };
    const u8 key[64] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F,  0x20, 0x21, 0x22, 0x23,  0x24, 0x25, 0x26, 0x27,  0x28, 0x29, 0x2A, 0x2B,  0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F };
    u8 digest_1[32];
    const u8 expected_1[32] = { 0x8B, 0xB9, 0xA1, 0xDB,  0x98, 0x06, 0xF2, 0x0D,  0xF7, 0xF7, 0x7B, 0x82,  0x13, 0x8C, 0x79, 0x14,  0xD1, 0x74, 0xD5, 0x9E,  0x13, 0xDC, 0x4D, 0x01,  0x69, 0xC9, 0x05, 0x7B,  0x13, 0x3E, 0x1D, 0x62 };
    hmac_1 = hmac_new();
    hmac_init(hmac_1, key, 64, SHA256);

    hmac_update(hmac_1, data, 34);
    hmac_final(hmac_1, digest_1);

    res_1 = memcmp(digest_1, expected_1, 32);
    if(!res_1)
    {
        ++pass;
        printf("\033[32m1. 'Sample message for keylen=blocklen' (%d/%d)\033[0m\n", ++test_idx, TEST_CNT);
    }
    else
    {
        ++fail;
        printf("\033[31m1. 'Sample message for keylen=blocklen' (%d/%d)\033[0m\n", ++test_idx, TEST_CNT);
    }

    /* test 2. msg='Sample message for keylen=blocklen', hash func='sha 256' */
    CgrophyHmac *hmac_2;
    int res_2;
    const u8 data_2[34] = { 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x6B, 0x65, 0x79, 0x6C, 0x65, 0x6E, 0x3C, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x6C, 0x65, 0x6E };
    const u8 key_2[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,  0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,  0x1C, 0x1D, 0x1E, 0x1F };
    u8 digest_2[32];
    const u8 expected_2[32] = { 0xA2, 0x8C, 0xF4, 0x31, 0x30, 0xEE, 0x69, 0x6A, 0x98, 0xF1, 0x4A, 0x37,  0x67, 0x8B, 0x56, 0xBC,  0xFC, 0xBD, 0xD9, 0xE5,  0xCF, 0x69, 0x71, 0x7F,  0xEC, 0xF5, 0x48, 0x0F,  0x0E, 0xBD, 0xF7, 0x90 };
    hmac_2 = hmac_new();
    hmac_init(hmac_2, key_2, 32, SHA256);

    hmac_update(hmac_2, data_2, 34);
    hmac_final(hmac_2, digest_2);

    res_2 = memcmp(digest_2, expected_2, 32);
    if(!res_2)
    {
        ++pass;
        printf("\033[32m2. 'Sample message for keylen<blocklen' (%d/%d)\033[0m\n", ++test_idx, TEST_CNT);
    }
    else
    {
        ++fail;
        printf("\033[31m2. 'Sample message for keylen<blocklen' (%d/%d)\033[0m\n", ++test_idx, TEST_CNT);
    }

    /* summarize */
    printf("\n\033[32mPass: %d\033[0m\n", pass);
    printf("\033[31mFail: %d\033[0m\n", fail);
    assert(pass+fail == TEST_CNT);
    printf("Total: %d", TEST_CNT);
}

#endif
