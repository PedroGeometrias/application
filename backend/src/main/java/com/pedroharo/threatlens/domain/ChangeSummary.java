package com.pedroharo.threatlens.domain;

import java.time.Instant;
import java.util.List;

public record ChangeSummary(
        boolean previousAvailable,
        String previousInvestigationId,
        Instant previousTimestamp,
        int scoreDelta,
        int maliciousDelta,
        int pulseDelta,
        boolean verdictChanged,
        String summary,
        List<String> changes
) {
    public static ChangeSummary firstObservation() {
        return new ChangeSummary(false, null, null, 0, 0, 0, false,
                "First recorded observation for this indicator.", List.of());
    }
}
