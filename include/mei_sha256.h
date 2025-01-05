#ifndef MEI_SHA256_H
#define MEI_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct SHA256_CTX
{
    uint32_t state[8];
    uint64_t bit_len;
    uint32_t data_len;
    uint8_t data[64];
} SHA256_CTX;

static const uint32_t K[64] = {
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

static _Thread_local uint8_t hash[32];
static _Thread_local char hashStr[65];

static inline uint32_t load32(const uint8_t* ptr)
{
    const uint8_t* p = ptr;
    return (uint32_t)p[0] << 24 |
           (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  |
           (uint32_t)p[3];
}

static inline void store32(uint8_t* ptr, const uint32_t x)
{
    uint8_t* p = ptr;
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static inline void mei_sha256_transform(SHA256_CTX* ctx, const uint8_t data[])
{
    uint32_t m[64];

    for (int i = 0; i < 16; ++i)
        m[i] = load32(data + i * 4);

    for (int i = 16; i < 64; i += 8)
    {
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
        m[i+1] = SIG1(m[i-1]) + m[i-6] + SIG0(m[i-14]) + m[i-15];
        m[i+2] = SIG1(m[i]) + m[i-5] + SIG0(m[i-13]) + m[i-14];
        m[i+3] = SIG1(m[i+1]) + m[i-4] + SIG0(m[i-12]) + m[i-13];
        m[i+4] = SIG1(m[i+2]) + m[i-3] + SIG0(m[i-11]) + m[i-12];
        m[i+5] = SIG1(m[i+3]) + m[i-2] + SIG0(m[i-10]) + m[i-11];
        m[i+6] = SIG1(m[i+4]) + m[i-1] + SIG0(m[i-9]) + m[i-10];
        m[i+7] = SIG1(m[i+5]) + m[i] + SIG0(m[i-8]) + m[i-9];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (int i = 0; i < 64; ++i)
    {
        const uint32_t t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        const uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static inline void mei_sha256_init(SHA256_CTX* ctx)
{
    ctx->data_len = 0;
    ctx->bit_len = 0;
    ctx->state[0] = 0x6A09E667;
    ctx->state[1] = 0xBB67AE85;
    ctx->state[2] = 0x3C6EF372;
    ctx->state[3] = 0xA54FF53A;
    ctx->state[4] = 0x510E527F;
    ctx->state[5] = 0x9B05688C;
    ctx->state[6] = 0x1F83D9AB;
    ctx->state[7] = 0x5BE0CD19;
}

static inline void mei_sha256_update(SHA256_CTX* ctx, const uint8_t* data, const size_t len)
{
    for(size_t i = 0; i < len; ++i)
    {
        ctx->data[ctx->data_len] = data[i];
        ctx->data_len++;
        if (ctx->data_len == 64)
        {
            mei_sha256_transform(ctx, ctx->data);
            ctx->bit_len += 512;
            ctx->data_len = 0;
        }
    }
}

static inline void mei_sha256_final(SHA256_CTX* ctx, uint8_t* hash)
{
    size_t i = ctx->data_len;

    if(ctx->data_len < 56)
    {
        ctx->data[i++] = 0x80;
        memset(ctx->data + i, 0, 56-i);
    }
    else
    {
        ctx->data[i++] = 0x80;
        memset(ctx->data + i, 0, 64-i);
        mei_sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bit_len += ctx->data_len * 8;
    ctx->data[63] = (uint8_t)ctx->bit_len;
    ctx->data[62] = (uint8_t)(ctx->bit_len >> 8);
    ctx->data[61] = (uint8_t)(ctx->bit_len >> 16);
    ctx->data[60] = (uint8_t)(ctx->bit_len >> 24);
    ctx->data[59] = (uint8_t)(ctx->bit_len >> 32);
    ctx->data[58] = (uint8_t)(ctx->bit_len >> 40);
    ctx->data[57] = (uint8_t)(ctx->bit_len >> 48);
    ctx->data[56] = (uint8_t)(ctx->bit_len >> 56);
    mei_sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; i++)
        store32(hash + i * 4, ctx->state[i]);
}

static inline void mei_sha256_hash(const uint8_t* data, const size_t len, uint8_t hash[32])
{
    SHA256_CTX ctx;
    mei_sha256_init(&ctx);
    mei_sha256_update(&ctx, data, len);
    mei_sha256_final(&ctx, hash);
}

static inline char* mei_sha256(const char* data)
{
    SHA256_CTX ctx;

    mei_sha256_init(&ctx);
    mei_sha256_update(&ctx, (const uint8_t*)data, strlen(data));
    mei_sha256_final(&ctx, hash);

    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < 32; ++i)
    {
        hashStr[i * 2] = hex[hash[i] >> 4];
        hashStr[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    hashStr[64] = '\0';

    return hashStr;
}

#ifdef __cplusplus
}
#endif

#endif /* MEI_SHA256_H */
