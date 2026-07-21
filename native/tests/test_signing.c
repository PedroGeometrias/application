#include "signing.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *stream_for(const char *value)
{
    FILE *stream = tmpfile();
    assert(stream != NULL);
    assert(fwrite(value, 1, strlen(value), stream) == strlen(value));
    rewind(stream);
    return stream;
}

int main(void)
{
    const char *private_path = "build/test-private.pem";
    const char *public_path = "build/test-public.pem";
    unsigned char *signature = NULL;
    size_t signature_length = 0;
    FILE *input;

    assert(signing_generate_key_pair(private_path, public_path, 2048) == 0);

    input = stream_for("signed investigation payload");
    assert(signing_sign_stream(private_path, input, &signature, &signature_length) == 0);
    fclose(input);
    assert(signature != NULL);
    assert(signature_length > 0);

    input = stream_for("signed investigation payload");
    assert(signing_verify_stream(public_path, input, signature, signature_length) == 1);
    fclose(input);

    input = stream_for("tampered investigation payload");
    assert(signing_verify_stream(public_path, input, signature, signature_length) == 0);
    fclose(input);

    free(signature);
    assert(remove(private_path) == 0);
    assert(remove(public_path) == 0);
    puts("signing tests passed");
    return 0;
}
