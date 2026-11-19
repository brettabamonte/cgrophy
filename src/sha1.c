/*
* https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
*/

#include "hash.h"
#include "sha1.h"
#include "types.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <malloc.h>
#endif

#define BUFFER_SIZE 64

#define rol(value, bits) (((value) << (bits) | ((value) >> (32 - (bits)))))

/* sha1 algo expects 32-bit words to be in big endian */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(block,i) (block[i] = ((rol(block[i], 8) & 0x00FF00FF) | (rol(block[i], 24) & 0xFF00FF00)))
#else
#define blk0(block,i) (block[i])
#endif

/* operation on words 16 - 79 
S'1(Wt-3 XOR Wt-8 XOR Wt-14 XOR Wt-16) where S is circular left shift and 1 is the number of bits to shift
*/
#define blk(block, i) (block[i&15] = rol(block[(i+13)&15] ^ block[(i+8)&15] ^ block[(i+2)&15] ^ block[i&15], 1))

#define f1(b,c,d) ((b & c) | (~b & d))
#define f2_4(b,c,d) (b ^ c ^ d)
#define f3(b,c,d) ((b & c) | (b & d) | (c & d))

Sha1Ctx *new(void);
void sha1_init(CgrophyHashFunc *obj);
void sha1_update(CgrophyHashFunc *obj, u8 *ptr, size_t len);
void sha1_digest(CgrophyHashFunc *obj, u8 *digest);
void sha1_destroy(CgrophyHashFunc *obj);

static void sha1_transform(u32 state[5], const u8 buffer[64]);

typedef struct Sha1Ctx{
    CgrophyHashFunc o;
	u32 count[2]; /* count of bits in msg. use two 32 bit #s to represent single 64 bit #. got from redis implementation */
	u32 state[5];
	u8 buffer[BUFFER_SIZE]; /* 512-bit buffer */
}Sha1Ctx;

const HashFunctionPrototype hash_function_prototype_sha1 = {
                                                .new = &sha1_new,
                                                .block_size = 64,
                                                .digest_size = 20,
                                               };

/* public api implementation */

Sha1Ctx *sha1_new(void)
{
    Sha1Ctx *new;
    CgrophyHashFuncVTable *vtable;

    new = (Sha1Ctx*)malloc(sizeof(Sha1Ctx));

    if (new == NULL)
    {
        return NULL;
    }

    vtable = (CgrophyHashFuncVTable *)malloc(sizeof(*vtable));

    if (vtable == NULL)
    {
        return NULL;
    }

    vtable->init = &sha1_init;
    vtable->update = sha1_update;
    vtable->final = sha1_final;
    vtable->destroy = sha1_destroy;

    new->o.type = SHA1;
    new->o.vtable = vtable;

    return new;
}

void sha1_init(CgrophyHashFunc *obj)
{
    Sha1Ctx *self;
    self = (Sha1Ctx *)obj;

	self->count[0] = self->count[1] = 0;

	self->state[0] = 0x67452301;
	self->state[1] = 0xEFCDAB89;
	self->state[2] = 0x98BADCFE;
	self->state[3] = 0x10325476;
	self->state[4] = 0xC3D2E1F0;
	memset(self->buffer, 0xEE, BUFFER_SIZE);
}

void sha1_update(CgrophyHashFunc *obj, u8 *ptr, size_t len)
{
    Sha1Ctx *self;
	u32 i, j;

    self = (Sha1Ctx *)obj;
	
	/* update count of bits in msg */
	j = self->count[0];
	if((self->count[0] += len << 3) < j)
		self->count[1]++;
	self->count[1] += (len >> 29);

	/* get bytes in buffer % 64. let's us see if the new data length + bytes in buffer are enough for 512-bit block */
	j = (j >> 3) & 63;
	if ((j + len) > 63)
	{
		memcpy(&self->buffer[j], ptr, (i = 64 - j));
		sha1_transform(self->state, self->buffer);

		/* keep processing 512-bit blocks as long as we have them */
		for ( ; i + 63 < len; i += 64)
			sha1_transform(self->state, &ptr[i]);
		j = 0;
	}
	else
		i = 0;

	/* buffer any bytes that couldn't be used to complete 512-bit block */
	memcpy(&self->buffer[j], &ptr[i], len - i);
}

void sha1_final(CgrophyHashFunc *obj, u8 *digest)
{
    Sha1Ctx *self;
	u16 i;
	u8 msg_len[8];
	u8 c;

    self = (Sha1Ctx *)obj;

	for (i = 0; i < 8; i++)
	{
		msg_len[i] = (u8)((self->count[i >= 4 ? 0 : 1] >> ((3 - (i & 3)) * 8)) & 255);
	}
	c = 0200;
	sha1_update(self, &c, 1);
	while((self->count[0] & 504) != 448)
	{
		c = 0000;
		sha1_update(self, &c, 1);
	}
	sha1_update(self, msg_len, 8);
	for (i = 0; i < 20; i++)
	{
		digest[i] = (u8)((self->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	
}

void sha1_destroy(CgrophyHashFunc *obj)
{
    assert(obj);
    free(obj->vtable);
    free(obj);
}

/* internals */


static void sha1_transform(u32 *state, const u8 buffer[64])
{
	u32 a, b, c, d, e; /* working vars */
	u32 word_stream[16];
	u32 temp;
	int t;

	memcpy(word_stream, buffer, 64);
	
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];

	for(t = 0; t < 80; t++)
	{
		if(t <= 15)
		{
			temp = rol(a, 5) + f1(b,c,d) + e + blk0(word_stream, t) + 0x5A827999;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		}
		else if(t <= 19)
		{
			temp = rol(a, 5) + f1(b,c,d) + e + blk(word_stream, t) + 0x5A827999;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		}
		else if(t <= 39)
		{
			temp = rol(a, 5) + f2_4(b,c,d) + e + blk(word_stream, t) + 0x6ED9EBA1;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		}
		else if(t <= 59)
		{
			temp = rol(a, 5) + f3(b,c,d) + e + blk(word_stream, t) + 0x8F1BBCDC;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		}
		else if(t <= 79)
		{
			temp = rol(a, 5) + f2_4(b,c,d) + e + blk(word_stream, t) + 0xCA62C1D6;
			e = d;
			d = c;
			c = rol(b,30);
			b = a;
			a = temp;
		}
		else
		{
			assert(0);
		}
	}
	
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;

	a = b = c = d = e = 0;
}

