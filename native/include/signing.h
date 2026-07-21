#ifndef THREATLENS_SIGNING_H
#define THREATLENS_SIGNING_H

#include <stddef.h>
#include <stdio.h>

int signing_generate_key_pair(const char *private_key_path,
                              const char *public_key_path,
                              int bits);
int signing_sign_stream(const char *private_key_path,
                        FILE *input,
                        unsigned char **signature,
                        size_t *signature_length);
int signing_verify_stream(const char *public_key_path,
                          FILE *input,
                          const unsigned char *signature,
                          size_t signature_length);
char *signing_base64_encode(const unsigned char *data, size_t length);
unsigned char *signing_base64_decode(const char *encoded, size_t *length);

#endif
