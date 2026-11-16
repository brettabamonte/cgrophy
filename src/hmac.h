#ifndef _HMAC_H
#define _HMAC_H

struct CgrophyHashFunc {
    void (*init)(CgrophyHashFunc *obj);
    void (*update)(CgrophyHashFunc *obj, unsigned char *ptr, size_t len);
    void (*final)(CgrophyHashFunc *obj, unsigned char *digest);
    u16 digest_size;
};

struct CgrophyHmac {
    unsigned char   *key;
    CgrophyHashFunc *hash_function;
    void (*update)(CgrophyHmac *obj, unsigned char *ptr, size_t len);
    void (*final)(CgrophyHmac *obj, unsigned char *digest);
};

#endif
