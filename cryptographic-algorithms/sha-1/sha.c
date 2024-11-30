#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 64  // 512 bytes
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))     // leftrotate operation

typedef struct {
    uint32_t h[5];
    uint64_t length;
    uint8_t block[BLOCK_SIZE];
    uint32_t index;
} SHA1_Obj;

void SHA1_Init(SHA1_Obj *o) {
    // initialize hashes
    o->h[0] = 0x67452301; o->h[1] = 0xEFCDAB89; o->h[2] = 0x98BADCFE;
    o->h[3] = 0x10325476; o->h[4] = 0xC3D2E1F0;
    o->length = o->index = 0;
}

void SHA1_ProcessBlock(SHA1_Obj *o) {
    uint32_t w[80], a, b, c, d, e, temp;
    for (int i = 0; i < 16; i++) 
        w[i] = (o->block[i*4] << 24) | (o->block[i*4+1] << 16) | (o->block[i*4+2] << 8) | o->block[i*4+3];
    for (int i = 16; i < 80; i++) 
        w[i] = ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    
    a = o->h[0]; b = o->h[1]; c = o->h[2]; d = o->h[3]; e = o->h[4];
    // main loop 
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            temp = ROTL(a, 5) + ((b & c) | (~b & d)) + e + w[i] + 0x5A827999;
        } else if (i < 40) {
            temp = ROTL(a, 5) + (b ^ c ^ d) + e + w[i] + 0x6ED9EBA1;
        } else if (i < 60) {
            temp = ROTL(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8F1BBCDC;
        } else {
            temp = ROTL(a, 5) + (b ^ c ^ d) + e + w[i] + 0xCA62C1D6;
        }
        e = d; d = c; c = ROTL(b, 30); b = a; a = temp;
    }
    o->h[0] += a; o->h[1] += b; o->h[2] += c; o->h[3] += d; o->h[4] += e;
}

void SHA1_Update(SHA1_Obj *o, const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        o->block[o->index++] = data[i];
        o->length += 8;
        if (o->index == BLOCK_SIZE) { SHA1_ProcessBlock(o); o->index = 0; }
    }
}

void SHA1_Final(SHA1_Obj *o, uint8_t *hash) {
    uint64_t length = o->length;
    o->block[o->index++] = 0x80;
    if (o->index > 56) { while (o->index < BLOCK_SIZE) o->block[o->index++] = 0x00; SHA1_ProcessBlock(o); o->index = 0; }
    while (o->index < 56) o->block[o->index++] = 0x00;
    for (int i = 0; i < 8; i++) o->block[o->index++] = (length >> (56 - i * 8)) & 0xFF;
    SHA1_ProcessBlock(o);
    for (int i = 0; i < 5; i++) {
        hash[i * 4] = (o->h[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (o->h[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (o->h[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = o->h[i] & 0xFF;
    }
}

void SHA1_ToHex(const uint8_t *hash, char *output) {
    for (int i = 0; i < 20; i++) sprintf(output + i * 2, "%02x", hash[i]);
}

int main() {
    const char *message = "The quick brown fox jumps over the lazy dog";
    uint8_t hash[20];
    char hash_hex[41];
    
    SHA1_Obj o;
    SHA1_Init(&o);
    SHA1_Update(&o, (const uint8_t *)message, strlen(message));
    SHA1_Final(&o, hash);
    SHA1_ToHex(hash, hash_hex);
    
    printf("%s\n", hash_hex);
    return 0;
}
