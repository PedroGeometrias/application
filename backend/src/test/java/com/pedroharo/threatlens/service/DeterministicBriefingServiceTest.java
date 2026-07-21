package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.IndicatorType;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.ProviderStatus;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.RiskVerdict;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DeterministicBriefingServiceTest {
    private final DeterministicBriefingService service = new DeterministicBriefingService();

    @Test
    void neverDescribesZeroDetectionsAsSafe() {
        ProviderReport clean = new ProviderReport("provider", ProviderStatus.SUCCESS, "none",
                0, 0, 60, 30, 0, 0,
                null, null, null, null, null, List.of(), List.of(), NullNode.getInstance());
        String briefing = service.generate(
                new Indicator("example.com", "example.com", IndicatorType.DOMAIN),
                new RiskAssessment(0, RiskVerdict.NO_KNOWN_THREAT, List.of("NO_POSITIVE_SIGNALS")),
                List.of(clean), ChangeSummary.firstObservation());

        assertThat(briefing).containsIgnoringCase("no known threat");
        assertThat(briefing).containsIgnoringCase("does not prove");
        assertThat(briefing).doesNotContain(" is safe");
    }
}
