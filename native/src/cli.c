#include "ioc.h"
#include "sha256.h"
#include "signing.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s hash --stdin|<file>\n"
            "  %s classify <indicator>\n"
            "  %s assess <otx-pulses> <vt-malicious> <vt-suspicious> "
            "<reputation> <providers> <recent>\n"
            "  %s keygen <private.pem> <public.pem>\n"
            "  %s sign <private.pem> --stdin\n"
            "  %s verify <public.pem> <base64-signature> --stdin\n",
            program, program, program, program, program, program);
}

static int parse_integer(const char *value, int *output)
{
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < -100000 || parsed > 100000) {
        return -1;
    }
    *output = (int)parsed;
    return 0;
}

static int command_hash(const char *target)
{
    uint8_t digest[32];
    char hexadecimal[65];
    int result = strcmp(target, "--stdin") == 0
        ? sha256_stream(stdin, digest)
        : sha256_path(target, digest);
    if (result != 0) {
        perror("threatcore: hash");
        return EXIT_FAILURE;
    }
    sha256_hex(digest, hexadecimal);
    puts(hexadecimal);
    return EXIT_SUCCESS;
}

static int command_classify(const char *value)
{
    ioc_result result;
    if (ioc_classify(value, &result) != 1) {
        puts("{\"valid\":false,\"type\":\"INVALID\",\"normalized\":\"\"}");
        return 2;
    }
    printf("{\"valid\":true,\"type\":\"%s\",\"normalized\":\"%s\"}\n",
           ioc_type_name(result.type), result.normalized);
    return EXIT_SUCCESS;
}

static void print_reasons(unsigned int flags)
{
    struct reason { unsigned int flag; const char *name; } reasons[] = {
        { REASON_VT_MALICIOUS, "VT_MALICIOUS_ENGINES" },
        { REASON_VT_SUSPICIOUS, "VT_SUSPICIOUS_ENGINES" },
        { REASON_OTX_PULSES, "OTX_PULSE_MATCHES" },
        { REASON_NEGATIVE_REPUTATION, "NEGATIVE_COMMUNITY_REPUTATION" },
        { REASON_PROVIDER_AGREEMENT, "PROVIDER_AGREEMENT" },
        { REASON_RECENT_ACTIVITY, "RECENT_ACTIVITY" },
        { REASON_NO_POSITIVE_SIGNALS, "NO_POSITIVE_SIGNALS" },
        { REASON_NO_PROVIDER_DATA, "NO_PROVIDER_DATA" }
    };
    int first = 1;
    putchar('[');
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); ++i) {
        if ((flags & reasons[i].flag) != 0U) {
            printf("%s\"%s\"", first ? "" : ",", reasons[i].name);
            first = 0;
        }
    }
    putchar(']');
}

static int command_assess(char **arguments)
{
    int values[6];
    threat_assessment result;
    for (size_t i = 0; i < 6; ++i) {
        if (parse_integer(arguments[i], &values[i]) != 0) {
            fprintf(stderr, "threatcore: assess: invalid integer: %s\n", arguments[i]);
            return EXIT_FAILURE;
        }
    }
    threat_assess(values[0], values[1], values[2], values[3], values[4], values[5], &result);
    printf("{\"score\":%d,\"verdict\":\"%s\",\"reasons\":",
           result.score, threat_verdict_name(result.verdict));
    print_reasons(result.reason_flags);
    puts("}");
    return EXIT_SUCCESS;
}

static int command_sign(const char *key_path)
{
    unsigned char *signature = NULL;
    size_t signature_length = 0;
    char *encoded = NULL;
    int result = EXIT_FAILURE;

    if (signing_sign_stream(key_path, stdin, &signature, &signature_length) != 0) {
        fprintf(stderr, "threatcore: unable to sign input\n");
        goto cleanup;
    }
    encoded = signing_base64_encode(signature, signature_length);
    if (encoded == NULL) {
        fprintf(stderr, "threatcore: unable to encode signature\n");
        goto cleanup;
    }
    puts(encoded);
    result = EXIT_SUCCESS;

cleanup:
    free(encoded);
    free(signature);
    return result;
}

static int command_verify(const char *key_path, const char *encoded)
{
    unsigned char *signature;
    size_t signature_length = 0;
    int verification;

    signature = signing_base64_decode(encoded, &signature_length);
    if (signature == NULL) {
        fprintf(stderr, "threatcore: invalid base64 signature\n");
        return EXIT_FAILURE;
    }
    verification = signing_verify_stream(key_path, stdin, signature, signature_length);
    free(signature);
    if (verification < 0) {
        fprintf(stderr, "threatcore: unable to verify signature\n");
        return EXIT_FAILURE;
    }
    puts(verification == 1 ? "valid" : "invalid");
    return verification == 1 ? EXIT_SUCCESS : 3;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "hash") == 0 && argc == 3) {
        return command_hash(argv[2]);
    }
    if (strcmp(argv[1], "classify") == 0 && argc == 3) {
        return command_classify(argv[2]);
    }
    if (strcmp(argv[1], "assess") == 0 && argc == 8) {
        return command_assess(&argv[2]);
    }
    if (strcmp(argv[1], "keygen") == 0 && argc == 4) {
        if (signing_generate_key_pair(argv[2], argv[3], 3072) != 0) {
            fprintf(stderr, "threatcore: key generation failed\n");
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }
    if (strcmp(argv[1], "sign") == 0 && argc == 4 && strcmp(argv[3], "--stdin") == 0) {
        return command_sign(argv[2]);
    }
    if (strcmp(argv[1], "verify") == 0 && argc == 5 && strcmp(argv[4], "--stdin") == 0) {
        return command_verify(argv[2], argv[3]);
    }

    usage(argv[0]);
    return EXIT_FAILURE;
}
