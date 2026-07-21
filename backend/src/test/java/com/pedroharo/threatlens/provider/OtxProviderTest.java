package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.IndicatorType;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

class OtxProviderTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final OtxProvider provider = new OtxProvider(null, mapper, null);

    @Test
    void normalizesPulseEvidenceWithoutDependingOnProviderSpecificJsonElsewhere() throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/otx-demo.json")) {
            var raw = mapper.readTree(input);
            var report = provider.normalize(raw,
                    new Indicator("demo.example", "demo.example", IndicatorType.DOMAIN));

            assertThat(report.pulseCount()).isEqualTo(4);
            assertThat(report.reputation()).isEqualTo(-4);
            assertThat(report.tags()).contains("phishing", "credential-theft");
            assertThat(report.evidence()).hasSize(4);
            assertThat(report.evidence()).allSatisfy(item ->
                    assertThat(item.reference()).startsWith("https://otx.alienvault.com/pulse/"));
            assertThat(report.succeeded()).isTrue();
        }
    }

    @Test
    void demoEvidenceDoesNotLinkToNonexistentSyntheticPulses() {
        var demoProvider = new OtxProvider(null, mapper,
                new ThreatLensProperties(true, null, null, null, null, null));
        var indicator = new Indicator("portal-update.example", "portal-update.example",
                IndicatorType.DOMAIN);

        var report = demoProvider.investigate(indicator);

        assertThat(report.evidence()).allSatisfy(item -> assertThat(item.reference()).isNull());
        assertThat(report.raw().path("indicator").asText()).isEqualTo("portal-update.example");
        assertThat(report.raw().path("type").asText()).isEqualTo("domain");
    }
}
