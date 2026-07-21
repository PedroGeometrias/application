#include "ioc.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void check(const char *value, ioc_type type, const char *normalized)
{
    ioc_result result;
    assert(ioc_classify(value, &result) == 1);
    assert(result.type == type);
    assert(strcmp(result.normalized, normalized) == 0);
}

int main(void)
{
    ioc_result invalid;
    threat_assessment assessment;

    check(" 8.8.8.8 ", IOC_IPV4, "8.8.8.8");
    check("2001:0db8:0:0:0:0:0:1", IOC_IPV6, "2001:db8::1");
    check("Example.COM.", IOC_DOMAIN, "example.com");
    check("D41D8CD98F00B204E9800998ECF8427E", IOC_MD5,
          "d41d8cd98f00b204e9800998ecf8427e");
    check("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOC_SHA1,
          "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    check("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          IOC_SHA256,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert(ioc_classify("not a domain", &invalid) == 0);
    assert(ioc_classify("-bad.example", &invalid) == 0);

    threat_assess(4, 7, 1, -5, 2, 1, &assessment);
    assert(assessment.verdict == VERDICT_HIGH_RISK);
    assert(assessment.score == 100);

    threat_assess(0, 0, 0, 0, 2, 0, &assessment);
    assert(assessment.verdict == VERDICT_NO_KNOWN_THREAT);
    assert(assessment.score == 0);

    puts("ioc tests passed");
    return 0;
}
