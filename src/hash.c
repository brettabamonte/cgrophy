
#include "hash.h"

#include <assert.h>

extern HashFunctionPrototype hash_function_prototype_sha1;
extern HashFunctionPrototype hash_function_prototype_sha256;

CgrophyHashFunc *hash_function_factory(CgrophyHashFuncType type)
{
    switch(type)
    {
        case SHA1:
        {
            return hash_function_prototype_sha1.new();
        } break;
        case SHA256:
        {
            return hash_function_prototype_sha256.new();
        } break;
        default:
            assert(0);
    }
}

void hash_function_init(CgrophyHashFunc *self)
{
    const CgrophyHashFuncVTable *vtable = self->vtable;
    if (vtable->init)
    {
        vtable->init(self);
    }
    else
    {
        assert(0);
    }
}

void hash_function_update(CgrophyHashFunc *self, unsigned char *ptr, size_t len)
{
    const CgrophyHashFuncVTable *vtable = self->vtable;
    if (vtable->update)
    {
        vtable->update(self, ptr, len);
    }
    else
    {
        assert(0);
    }
}

void hash_function_final(CgrophyHashFunc *self, unsigned char *digest)
{
    const CgrophyHashFuncVTable *vtable = self->vtable;
    if (vtable->final)
    {
        vtable->final(self, digest);
    }
    else
    {
        assert(0);
    }
}

void hash_function_destroy(CgrophyHashFunc *self)
{
    const CgrophyHashFuncVTable *vtable = self->vtable;
    if (vtable->destroy)
    {
        vtable->destroy(self);
    }
    else
    {
        assert(0);
    }
}

u16 hash_function_digest_size(CgrophyHashFuncType type)
{
    switch(type)
    {
        case SHA1:
        {
            return hash_function_prototype_sha1.digest_size;
        }break;
        case SHA256:
        {
            return hash_function_prototype_sha256.digest_size;
        }break;
        default:
            assert(0);
    }
}

u16 hash_function_block_size(CgrophyHashFuncType type)
{
    switch(type)
    {
        case SHA1:
        {
            return hash_function_prototype_sha1.block_size;
        }break;
        case SHA256:
        {
            return hash_function_prototype_sha256.block_size;
        }break;
        default:
            assert(0);
    }
}

