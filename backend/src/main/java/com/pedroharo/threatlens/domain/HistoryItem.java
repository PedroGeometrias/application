package com.pedroharo.threatlens.domain;

import java.time.Instant;

public record HistoryItem(
        String id,
        String indicator,
        String normalizedIndicator,
        IndicatorType indicatorType,
        RiskVerdict verdict,
        int riskScore,
        int providerCount,
        Instant createdAt,
        String briefing,
        String integrityHash
) {}
