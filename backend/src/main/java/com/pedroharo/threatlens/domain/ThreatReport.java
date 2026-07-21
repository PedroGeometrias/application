package com.pedroharo.threatlens.domain;

import java.time.Instant;
import java.util.List;

public record ThreatReport(
        String id,
        Indicator indicator,
        RiskAssessment assessment,
        List<ProviderReport> providers,
        String briefing,
        String briefingSource,
        ChangeSummary comparison,
        Instant investigatedAt,
        String integrityHash,
        boolean nativeCoreUsed,
        boolean cachedEvidence
) {}
