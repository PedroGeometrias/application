#include "signing.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

static EVP_PKEY *read_private_key(const char *path)
{
    FILE *stream = fopen(path, "rb");
    EVP_PKEY *key;
    if (stream == NULL) {
        return NULL;
    }
    key = PEM_read_PrivateKey(stream, NULL, NULL, NULL);
    fclose(stream);
    return key;
}

static EVP_PKEY *read_public_key(const char *path)
{
    FILE *stream = fopen(path, "rb");
    EVP_PKEY *key;
    if (stream == NULL) {
        return NULL;
    }
    key = PEM_read_PUBKEY(stream, NULL, NULL, NULL);
    fclose(stream);
    return key;
}

static int configure_pss(EVP_PKEY_CTX *context)
{
    return EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) > 0
        && EVP_PKEY_CTX_set_rsa_pss_saltlen(context, RSA_PSS_SALTLEN_DIGEST) > 0;
}

int signing_generate_key_pair(const char *private_key_path,
                              const char *public_key_path,
                              int bits)
{
    EVP_PKEY_CTX *context = NULL;
    EVP_PKEY *key = NULL;
    FILE *private_stream = NULL;
    FILE *public_stream = NULL;
    int result = -1;

    context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (context == NULL
            || EVP_PKEY_keygen_init(context) <= 0
            || EVP_PKEY_CTX_set_rsa_keygen_bits(context, bits) <= 0
            || EVP_PKEY_keygen(context, &key) <= 0) {
        goto cleanup;
    }

    private_stream = fopen(private_key_path, "wb");
    public_stream = fopen(public_key_path, "wb");
    if (private_stream == NULL || public_stream == NULL) {
        goto cleanup;
    }
    if (PEM_write_PrivateKey(private_stream, key, NULL, NULL, 0, NULL, NULL) != 1
            || PEM_write_PUBKEY(public_stream, key) != 1) {
        goto cleanup;
    }
    result = 0;

cleanup:
    if (private_stream != NULL) fclose(private_stream);
    if (public_stream != NULL) fclose(public_stream);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(context);
    return result;
}

static int digest_stream(EVP_MD_CTX *context, FILE *input, int signing)
{
    unsigned char buffer[16 * 1024];
    size_t count;
    while ((count = fread(buffer, 1, sizeof(buffer), input)) > 0) {
        const int ok = signing
            ? EVP_DigestSignUpdate(context, buffer, count)
            : EVP_DigestVerifyUpdate(context, buffer, count);
        if (ok != 1) {
            return -1;
        }
    }
    return ferror(input) ? -1 : 0;
}

int signing_sign_stream(const char *private_key_path,
                        FILE *input,
                        unsigned char **signature,
                        size_t *signature_length)
{
    EVP_PKEY *key = read_private_key(private_key_path);
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *key_context = NULL;
    int result = -1;

    if (key == NULL || input == NULL || signature == NULL || signature_length == NULL) {
        goto cleanup;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL
            || EVP_DigestSignInit(context, &key_context, EVP_sha256(), NULL, key) != 1
            || !configure_pss(key_context)
            || digest_stream(context, input, 1) != 0
            || EVP_DigestSignFinal(context, NULL, signature_length) != 1) {
        goto cleanup;
    }

    *signature = malloc(*signature_length);
    if (*signature == NULL
            || EVP_DigestSignFinal(context, *signature, signature_length) != 1) {
        free(*signature);
        *signature = NULL;
        goto cleanup;
    }
    result = 0;

cleanup:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return result;
}

int signing_verify_stream(const char *public_key_path,
                          FILE *input,
                          const unsigned char *signature,
                          size_t signature_length)
{
    EVP_PKEY *key = read_public_key(public_key_path);
    EVP_MD_CTX *context = NULL;
    EVP_PKEY_CTX *key_context = NULL;
    int result = -1;

    if (key == NULL || input == NULL || signature == NULL) {
        goto cleanup;
    }
    context = EVP_MD_CTX_new();
    if (context == NULL
            || EVP_DigestVerifyInit(context, &key_context, EVP_sha256(), NULL, key) != 1
            || !configure_pss(key_context)
            || digest_stream(context, input, 0) != 0) {
        goto cleanup;
    }
    result = EVP_DigestVerifyFinal(context, signature, signature_length) == 1 ? 1 : 0;

cleanup:
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    return result;
}

char *signing_base64_encode(const unsigned char *data, size_t length)
{
    size_t encoded_length;
    char *encoded;

    if (length > INT_MAX) {
        return NULL;
    }
    encoded_length = 4U * ((length + 2U) / 3U);
    encoded = malloc(encoded_length + 1U);
    if (encoded == NULL) {
        return NULL;
    }
    EVP_EncodeBlock((unsigned char *)encoded, data, (int)length);
    encoded[encoded_length] = '\0';
    return encoded;
}

unsigned char *signing_base64_decode(const char *encoded, size_t *length)
{
    const size_t encoded_length = encoded == NULL ? 0 : strlen(encoded);
    unsigned char *decoded;
    int decoded_length;
    size_t padding = 0;

    if (encoded == NULL || length == NULL || encoded_length == 0
            || encoded_length % 4U != 0 || encoded_length > INT_MAX) {
        return NULL;
    }
    decoded = malloc((encoded_length / 4U) * 3U + 1U);
    if (decoded == NULL) {
        return NULL;
    }
    decoded_length = EVP_DecodeBlock(decoded, (const unsigned char *)encoded,
                                     (int)encoded_length);
    if (decoded_length < 0) {
        free(decoded);
        return NULL;
    }
    if (encoded[encoded_length - 1] == '=') ++padding;
    if (encoded[encoded_length - 2] == '=') ++padding;
    *length = (size_t)decoded_length - padding;
    return decoded;
}
