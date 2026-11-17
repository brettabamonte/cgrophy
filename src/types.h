#ifndef _TYPES_H
#define _TYPES_H

typedef unsigned char 		u8;
typedef unsigned long 		u16;
typedef unsigned int 		u32;
typedef unsigned long long  u64;

typedef struct CgrophyHashFunc CgrophyHashFunc;
typedef struct CgrophyHmac CgrophyHmac;

struct CgrophyHashFunc {
    CgrophyHashFunc *(*new)(void);
    void (*init)(CgrophyHashFunc *obj);
    void (*update)(CgrophyHashFunc *obj, unsigned char *ptr, size_t len);
    void (*final)(CgrophyHashFunc *obj, unsigned char *digest);
    u16 digest_size;
    u16 block_size;
};


#endif
