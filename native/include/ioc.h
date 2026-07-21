#ifndef THREATLENS_IOC_H
#define THREATLENS_IOC_H

#include <stddef.h>

#define IOC_NORMALIZED_MAX 254

typedef enum {
    IOC_INVALID = 0,
    IOC_IPV4,
    IOC_IPV6,
    IOC_DOMAIN,
    IOC_MD5,
    IOC_SHA1,
    IOC_SHA256
} ioc_type;

typedef struct {
    ioc_type type;
    char normalized[IOC_NORMALIZED_MAX + 1];
} ioc_result;

typedef enum {
    VERDICT_INCONCLUSIVE = 0,
    VERDICT_NO_KNOWN_THREAT,
    VERDICT_SUSPICIOUS,
    VERDICT_HIGH_RISK
} threat_verdict;

typedef struct {
    int score;
    threat_verdict verdict;
    unsigned int reason_flags;
} threat_assessment;

enum {
    REASON_VT_MALICIOUS = 1U << 0,
    REASON_VT_SUSPICIOUS = 1U << 1,
    REASON_OTX_PULSES = 1U << 2,
    REASON_NEGATIVE_REPUTATION = 1U << 3,
    REASON_PROVIDER_AGREEMENT = 1U << 4,
    REASON_RECENT_ACTIVITY = 1U << 5,
    REASON_NO_POSITIVE_SIGNALS = 1U << 6,
    REASON_NO_PROVIDER_DATA = 1U << 7
};

int ioc_classify(const char *value, ioc_result *result);
const char *ioc_type_name(ioc_type type);
void threat_assess(int otx_pulses,
                   int vt_malicious,
                   int vt_suspicious,
                   int reputation,
                   int successful_providers,
                   int recent_activity,
                   threat_assessment *result);
const char *threat_verdict_name(threat_verdict verdict);

#endif
