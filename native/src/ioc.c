#include "ioc.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int is_hex_string(const char *value, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        if (!isxdigit((unsigned char)value[i])) {
            return 0;
        }
    }
    return 1;
}

static int normalize_hash(const char *value, size_t length, ioc_result *result)
{
    if (!is_hex_string(value, length)) {
        return 0;
    }
    for (size_t i = 0; i < length; ++i) {
        result->normalized[i] = (char)tolower((unsigned char)value[i]);
    }
    result->normalized[length] = '\0';
    result->type = length == 32 ? IOC_MD5 : (length == 40 ? IOC_SHA1 : IOC_SHA256);
    return 1;
}

static int normalize_ip(const char *value, ioc_result *result)
{
    unsigned char address[sizeof(struct in6_addr)];
    int family;

    if (inet_pton(AF_INET, value, address) == 1) {
        family = AF_INET;
        result->type = IOC_IPV4;
    } else if (inet_pton(AF_INET6, value, address) == 1) {
        family = AF_INET6;
        result->type = IOC_IPV6;
    } else {
        return 0;
    }

    if (inet_ntop(family, address, result->normalized, sizeof(result->normalized)) == NULL) {
        result->type = IOC_INVALID;
        return 0;
    }
    return 1;
}

static int normalize_domain(const char *value, size_t length, ioc_result *result)
{
    size_t label_length = 0;
    int dot_seen = 0;

    if (length > 0 && value[length - 1] == '.') {
        --length;
    }
    if (length == 0 || length > 253 || value[0] == '-' || value[length - 1] == '-') {
        return 0;
    }

    for (size_t i = 0; i < length; ++i) {
        const unsigned char character = (unsigned char)value[i];
        if (character == '.') {
            if (label_length == 0 || label_length > 63 || value[i - 1] == '-') {
                return 0;
            }
            label_length = 0;
            dot_seen = 1;
            result->normalized[i] = '.';
            continue;
        }
        if (!(isalnum(character) || character == '-')) {
            return 0;
        }
        if (label_length == 0 && character == '-') {
            return 0;
        }
        ++label_length;
        result->normalized[i] = (char)tolower(character);
    }

    if (!dot_seen || label_length == 0 || label_length > 63) {
        return 0;
    }
    result->normalized[length] = '\0';
    result->type = IOC_DOMAIN;
    return 1;
}

int ioc_classify(const char *value, ioc_result *result)
{
    char trimmed[IOC_NORMALIZED_MAX + 1];
    const char *start;
    size_t length;

    if (value == NULL || result == NULL) {
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->type = IOC_INVALID;

    start = value;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        ++start;
    }
    length = strlen(start);
    while (length > 0 && isspace((unsigned char)start[length - 1])) {
        --length;
    }
    if (length == 0 || length > IOC_NORMALIZED_MAX) {
        return 0;
    }
    memcpy(trimmed, start, length);
    trimmed[length] = '\0';

    if ((length == 32 || length == 40 || length == 64)
            && normalize_hash(trimmed, length, result)) {
        return 1;
    }
    if (normalize_ip(trimmed, result)) {
        return 1;
    }
    if (normalize_domain(trimmed, length, result)) {
        return 1;
    }
    return 0;
}

const char *ioc_type_name(ioc_type type)
{
    switch (type) {
        case IOC_IPV4: return "IPV4";
        case IOC_IPV6: return "IPV6";
        case IOC_DOMAIN: return "DOMAIN";
        case IOC_MD5: return "MD5";
        case IOC_SHA1: return "SHA1";
        case IOC_SHA256: return "SHA256";
        default: return "INVALID";
    }
}

static int capped_product(int value, int multiplier, int maximum)
{
    if (value <= 0) {
        return 0;
    }
    if (value > maximum / multiplier) {
        return maximum;
    }
    return value * multiplier;
}

void threat_assess(int otx_pulses,
                   int vt_malicious,
                   int vt_suspicious,
                   int reputation,
                   int successful_providers,
                   int recent_activity,
                   threat_assessment *result)
{
    int score = 0;
    int positive_sources = 0;
    unsigned int reasons = 0;

    if (result == NULL) {
        return;
    }

    if (vt_malicious > 0) {
        score += capped_product(vt_malicious, 10, 60);
        reasons |= REASON_VT_MALICIOUS;
        ++positive_sources;
    }
    if (vt_suspicious > 0) {
        score += capped_product(vt_suspicious, 5, 20);
        reasons |= REASON_VT_SUSPICIOUS;
    }
    if (otx_pulses > 0) {
        score += capped_product(otx_pulses, 8, 40);
        reasons |= REASON_OTX_PULSES;
        ++positive_sources;
    }
    if (reputation < 0) {
        const int penalty = reputation < -15 ? 15 : -reputation;
        score += penalty;
        reasons |= REASON_NEGATIVE_REPUTATION;
    }
    if (positive_sources >= 2) {
        score += 10;
        reasons |= REASON_PROVIDER_AGREEMENT;
    }
    if (recent_activity) {
        score += 5;
        reasons |= REASON_RECENT_ACTIVITY;
    }
    if (score > 100) {
        score = 100;
    }

    result->score = score;
    result->reason_flags = reasons;
    if (successful_providers <= 0) {
        result->verdict = VERDICT_INCONCLUSIVE;
        result->reason_flags |= REASON_NO_PROVIDER_DATA;
    } else if (score >= 70 || vt_malicious >= 5 || otx_pulses >= 6) {
        result->verdict = VERDICT_HIGH_RISK;
    } else if (score >= 25 || vt_malicious > 0 || vt_suspicious > 0 || otx_pulses > 0) {
        result->verdict = VERDICT_SUSPICIOUS;
    } else {
        result->verdict = VERDICT_NO_KNOWN_THREAT;
        result->reason_flags |= REASON_NO_POSITIVE_SIGNALS;
    }
}

const char *threat_verdict_name(threat_verdict verdict)
{
    switch (verdict) {
        case VERDICT_NO_KNOWN_THREAT: return "NO_KNOWN_THREAT";
        case VERDICT_SUSPICIOUS: return "SUSPICIOUS";
        case VERDICT_HIGH_RISK: return "HIGH_RISK";
        default: return "INCONCLUSIVE";
    }
}
