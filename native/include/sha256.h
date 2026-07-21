#ifndef THREATLENS_SHA256_H
#define THREATLENS_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t block[64];
    size_t block_length;
} sha256_context;

void sha256_init(sha256_context *context);
void sha256_update(sha256_context *context, const uint8_t *data, size_t length);
void sha256_final(sha256_context *context, uint8_t digest[32]);
void sha256_hex(const uint8_t digest[32], char output[65]);
int sha256_stream(FILE *stream, uint8_t digest[32]);
int sha256_path(const char *path, uint8_t digest[32]);

#endif
