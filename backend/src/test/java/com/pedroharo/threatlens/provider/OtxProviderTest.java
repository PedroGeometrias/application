package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
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
            assertThat(report.succeeded()).isTrue();
        }
    }
}
