#ifndef _HASH_H
#define _HASH_H

#include "types.h"

#include <assert.h>

/* forward decs */
typedef struct HashFunctionPrototype HashFunctionPrototype;
typedef struct CgrophyHashFunc CgrophyHashFunc;
typedef struct CgrophyHashFuncVTable CgrophyHashFuncVTable;

/* public api */
typedef enum CgrophyHashFuncType {
    SHA1,
    SHA256
} CgrophyHashFuncType;

struct CgrophyHashFuncVTable {
    void (*init)(CgrophyHashFunc *self);
    void (*update)(CgrophyHashFunc *self, unsigned char *, size_t);
    void (*final)(CgrophyHashFunc *self, unsigned char *);
    void (*destroy)(CgrophyHashFunc *self);
};

struct CgrophyHashFunc {
    CgrophyHashFuncType     type;
    CgrophyHashFuncVTable   *vtable;
};

/* global prototypes each hash implemenation should make available for linking */
struct HashFunctionPrototype {
    CgrophyHashFunc*    (*new)(void);
    u16                 digest_size;
    u16                 block_size;
};

CgrophyHashFunc *hash_function_factory(CgrophyHashFuncType type);
void hash_function_init(CgrophyHashFunc *self);
void hash_function_update(CgrophyHashFunc *self, unsigned char *ptr, size_t len);
void hash_function_final(CgrophyHashFunc *self, unsigned char *digest);
void hash_function_destroy(CgrophyHashFunc *self);
u16 hash_function_block_size(CgrophyHashFuncType type);
u16 hash_function_digest_size(CgrophyHashFuncType type);

#endif
