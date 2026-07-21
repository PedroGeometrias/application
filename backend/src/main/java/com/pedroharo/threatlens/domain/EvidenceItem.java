package com.pedroharo.threatlens.domain;

public record EvidenceItem(
        String source,
        EvidenceSeverity severity,
        String category,
        String title,
        String detail,
        String reference
) {}
