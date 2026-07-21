package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.IndicatorType;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.ProviderStatus;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.RiskVerdict;
import com.pedroharo.threatlens.domain.ThreatReport;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ComparisonServiceTest {
    private final ComparisonService service = new ComparisonService();

    @Test
    void explainsMaterialChangesBetweenSnapshots() {
        ProviderReport oldProvider = provider(2, 1);
        ThreatReport previous = new ThreatReport("old",
                new Indicator("example.com", "example.com", IndicatorType.DOMAIN),
                new RiskAssessment(42, RiskVerdict.SUSPICIOUS, List.of()),
                List.of(oldProvider), "", "Deterministic", ChangeSummary.firstObservation(),
                Instant.parse("2026-07-01T00:00:00Z"), "hash", true, false);

        ChangeSummary result = service.compare(
                new RiskAssessment(80, RiskVerdict.HIGH_RISK, List.of()),
                List.of(provider(7, 4)), Optional.of(previous));

        assertThat(result.verdictChanged()).isTrue();
        assertThat(result.scoreDelta()).isEqualTo(38);
        assertThat(result.maliciousDelta()).isEqualTo(5);
        assertThat(result.pulseDelta()).isEqualTo(3);
        assertThat(result.changes()).hasSizeGreaterThanOrEqualTo(3);
    }

    private ProviderReport provider(int malicious, int pulses) {
        return new ProviderReport("provider", ProviderStatus.SUCCESS, "ok",
                malicious, 0, 0, 0, pulses, 0,
                null, null, null, null, null, List.of(), List.of(), NullNode.getInstance());
    }
}
