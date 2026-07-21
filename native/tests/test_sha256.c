#include "sha256.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check(const char *input, const char *expected)
{
    sha256_context context;
    uint8_t digest[32];
    char actual[65];
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)input, strlen(input));
    sha256_final(&context, digest);
    sha256_hex(digest, actual);
    assert(strcmp(actual, expected) == 0);
}

static void check_incremental(void)
{
    sha256_context context;
    uint8_t digest[32];
    char actual[65];
    uint8_t chunk[1000];

    memset(chunk, 'a', sizeof(chunk));
    sha256_init(&context);
    for (int i = 0; i < 1000; ++i) {
        sha256_update(&context, chunk, sizeof(chunk));
    }
    sha256_final(&context, digest);
    sha256_hex(digest, actual);
    assert(strcmp(actual,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
}

static void check_binary(void)
{
    sha256_context context;
    uint8_t input[256];
    uint8_t digest[32];
    char actual[65];

    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)i;
    sha256_init(&context);
    sha256_update(&context, input, sizeof(input));
    sha256_final(&context, digest);
    sha256_hex(digest, actual);
    assert(strcmp(actual,
            "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880") == 0);
}

int main(void)
{
    check("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check("The quick brown fox jumps over the lazy dog",
          "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    check_incremental();
    check_binary();
    puts("sha256 tests passed");
    return 0;
}
