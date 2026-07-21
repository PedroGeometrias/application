package com.pedroharo.threatlens.domain;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.List;

public record ProviderReport(
        String provider,
        ProviderStatus status,
        String message,
        int maliciousCount,
        int suspiciousCount,
        int harmlessCount,
        int undetectedCount,
        int pulseCount,
        int reputation,
        String country,
        String asn,
        String networkOwner,
        Instant firstSeen,
        Instant lastSeen,
        List<String> tags,
        List<EvidenceItem> evidence,
        JsonNode raw
) {
    public boolean succeeded() {
        return status == ProviderStatus.SUCCESS;
    }

    public boolean hasPositiveSignals() {
        return maliciousCount > 0 || suspiciousCount > 0 || pulseCount > 0 || reputation < 0;
    }
}
