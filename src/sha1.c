/*
* https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf
*/

#include "sha1.h"
#include "types.h"

#include <assert.h>
#include <stdlib.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <malloc.h>
#endif

#ifdef SHA1_TEST
#include <string.h>
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

static void sha1_transform(u32 state[5], const u8 buffer[64]);

typedef struct Sha1Ctx{
	u32 count[2]; /* count of bits in msg. use two 32 bit #s to represent single 64 bit #. got from redis implementation */
	u32 state[5];
	u8 buffer[BUFFER_SIZE]; /* 512-bit buffer */
}Sha1Ctx;

/* public api implementation */

Sha1Ctx *sha1_new(void)
{
    Sha1Ctx *new;
    new = (Sha1Ctx*)malloc(sizeof(Sha1Ctx));

    if (new == NULL)
    {
        return NULL;
    }

    return new;
}

void sha1_init(Sha1Ctx *ctx)
{
	ctx->count[0] = ctx->count[1] = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	memset(ctx->buffer, 0xEE, BUFFER_SIZE);
}

void sha1_update(Sha1Ctx *ctx, u8 *ptr, size_t len)
{
	u32 i, j;
	
	/* update count of bits in msg */
	j = ctx->count[0];
	if((ctx->count[0] += len << 3) < j)
		ctx->count[1]++;
	ctx->count[1] += (len >> 29);

	/* get bytes in buffer % 64. let's us see if the new data length + bytes in buffer are enough for 512-bit block */
	j = (j >> 3) & 63;
	if ((j + len) > 63)
	{
		memcpy(&ctx->buffer[j], ptr, (i = 64 - j));
		sha1_transform(ctx->state, ctx->buffer);

		/* keep processing 512-bit blocks as long as we have them */
		for ( ; i + 63 < len; i += 64)
			sha1_transform(ctx->state, &ptr[i]);
		j = 0;
	}
	else
		i = 0;

	/* buffer any bytes that couldn't be used to complete 512-bit block */
	memcpy(&ctx->buffer[j], &ptr[i], len - i);
}

void sha1_final(Sha1Ctx *ctx, u8 *digest)
{
	u16 i;
	u8 msg_len[8];
	u8 c;

	for (i = 0; i < 8; i++)
	{
		msg_len[i] = (u8)((ctx->count[i >= 4 ? 0 : 1] >> ((3 - (i & 3)) * 8)) & 255);
	}
	c = 0200;
	sha1_update(ctx, &c, 1);
	while((ctx->count[0] & 504) != 448)
	{
		c = 0000;
		sha1_update(ctx, &c, 1);
	}
	sha1_update(ctx, msg_len, 8);
	for (i = 0; i < 20; i++)
	{
		digest[i] = (u8)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
	}
	
	/* wipe ctx vars */
	memset(ctx, '\0', sizeof(*ctx));
}

void sha1_destroy(Sha1Ctx *ctx)
{
    assert(ctx);
    free(ctx);
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


#ifdef SHA1_TEST

int main(int argc, char **argv)
{
	(void)(argc);
	(void)(argv);

	/* test 1, 'abc' */
	Sha1Ctx ctx_1;
	u8 digest[20];
	char test_1[3] = "abc";
	u8 expected[20] = { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D };

	sha1_init(&ctx_1);
	sha1_update(&ctx_1, test_1, sizeof(test_1));
	sha1_final(&ctx_1, digest);

	assert(memcmp(expected, digest, 20) == 0);
	
	/* test 2, 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' */
	Sha1Ctx ctx_2;
	u8 digest_2[20];
	char test_2[56] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	u8 expected_2[20] = { 0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1 };

	sha1_init(&ctx_2);
	sha1_update(&ctx_2, test_2, sizeof(test_2));
	sha1_final(&ctx_2, digest_2);

	assert(memcmp(expected_2, digest_2, 20) == 0);

	/* test 3, 1M 'a' */
	Sha1Ctx ctx_3;
	u32 i;
	u8 digest_3[20];
	char test_3[1000000];

	i = 0;
	memset(test_3, 0x61, 1000000);
	u8 expected_3[20] = { 0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F };

	sha1_init(&ctx_3);
	while(i < 1000000)
	{
		sha1_update(&ctx_3, &test_3[i], 1000);
		i += 1000;
	}
	sha1_final(&ctx_3, digest_3);

	assert(memcmp(expected_3, digest_3, 20) == 0);
}

#endif
