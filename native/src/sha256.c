/*
 * Incremental SHA-256 implementation derived from Pedro Haro's original
 * standalone implementation. The public API and streaming design were added
 * for ThreatLens; the compression algorithm remains Pedro's implementation.
 */
#include "sha256.h"

#include <errno.h>
#include <string.h>

static const uint32_t round_constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static uint32_t rotate_right(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static void transform(sha256_context *context, const uint8_t block[64])
{
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (size_t i = 0; i < 16; ++i) {
        const size_t offset = i * 4;
        words[i] = ((uint32_t)block[offset] << 24U)
                 | ((uint32_t)block[offset + 1] << 16U)
                 | ((uint32_t)block[offset + 2] << 8U)
                 | (uint32_t)block[offset + 3];
    }

    for (size_t i = 16; i < 64; ++i) {
        const uint32_t sigma0 = rotate_right(words[i - 15], 7U)
                              ^ rotate_right(words[i - 15], 18U)
                              ^ (words[i - 15] >> 3U);
        const uint32_t sigma1 = rotate_right(words[i - 2], 17U)
                              ^ rotate_right(words[i - 2], 19U)
                              ^ (words[i - 2] >> 10U);
        words[i] = words[i - 16] + sigma0 + words[i - 7] + sigma1;
    }

    a = context->state[0];
    b = context->state[1];
    c = context->state[2];
    d = context->state[3];
    e = context->state[4];
    f = context->state[5];
    g = context->state[6];
    h = context->state[7];

    for (size_t i = 0; i < 64; ++i) {
        const uint32_t sum1 = rotate_right(e, 6U)
                            ^ rotate_right(e, 11U)
                            ^ rotate_right(e, 25U);
        const uint32_t choice = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + sum1 + choice + round_constants[i] + words[i];
        const uint32_t sum0 = rotate_right(a, 2U)
                            ^ rotate_right(a, 13U)
                            ^ rotate_right(a, 22U);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    context->state[4] += e;
    context->state[5] += f;
    context->state[6] += g;
    context->state[7] += h;
}

void sha256_init(sha256_context *context)
{
    static const uint32_t initial_state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    memcpy(context->state, initial_state, sizeof(initial_state));
    context->bit_length = 0;
    context->block_length = 0;
    memset(context->block, 0, sizeof(context->block));
}

void sha256_update(sha256_context *context, const uint8_t *data, size_t length)
{
    if (context == NULL || (data == NULL && length != 0)) {
        return;
    }

    for (size_t i = 0; i < length; ++i) {
        context->block[context->block_length++] = data[i];
        if (context->block_length == sizeof(context->block)) {
            transform(context, context->block);
            context->bit_length += 512U;
            context->block_length = 0;
        }
    }
}

void sha256_final(sha256_context *context, uint8_t digest[32])
{
    size_t index = context->block_length;

    context->block[index++] = 0x80U;
    if (index > 56) {
        while (index < 64) {
            context->block[index++] = 0;
        }
        transform(context, context->block);
        index = 0;
    }

    while (index < 56) {
        context->block[index++] = 0;
    }

    context->bit_length += (uint64_t)context->block_length * 8U;
    for (size_t i = 0; i < 8; ++i) {
        context->block[63U - i] = (uint8_t)(context->bit_length >> (i * 8U));
    }
    transform(context, context->block);

    for (size_t i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(context->state[i] >> 24U);
        digest[i * 4 + 1] = (uint8_t)(context->state[i] >> 16U);
        digest[i * 4 + 2] = (uint8_t)(context->state[i] >> 8U);
        digest[i * 4 + 3] = (uint8_t)context->state[i];
    }

    memset(context, 0, sizeof(*context));
}

void sha256_hex(const uint8_t digest[32], char output[65])
{
    static const char hexadecimal[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        output[i * 2] = hexadecimal[digest[i] >> 4U];
        output[i * 2 + 1] = hexadecimal[digest[i] & 0x0fU];
    }
    output[64] = '\0';
}

int sha256_stream(FILE *stream, uint8_t digest[32])
{
    uint8_t input[16 * 1024];
    sha256_context context;
    size_t bytes_read;

    if (stream == NULL || digest == NULL) {
        errno = EINVAL;
        return -1;
    }

    sha256_init(&context);
    while ((bytes_read = fread(input, 1, sizeof(input), stream)) > 0) {
        sha256_update(&context, input, bytes_read);
    }

    if (ferror(stream)) {
        return -1;
    }

    sha256_final(&context, digest);
    return 0;
}

int sha256_path(const char *path, uint8_t digest[32])
{
    FILE *stream;
    int result;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    stream = fopen(path, "rb");
    if (stream == NULL) {
        return -1;
    }
    result = sha256_stream(stream, digest);
    if (fclose(stream) != 0 && result == 0) {
        result = -1;
    }
    return result;
}
