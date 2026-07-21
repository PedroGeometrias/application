package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.IndicatorType;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

class VirusTotalProviderTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final VirusTotalProvider provider = new VirusTotalProvider(null, mapper, null);

    @Test
    void extractsEngineStatisticsAndOnlyActionableEngineEvidence() throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/fixtures/virustotal-demo.json")) {
            var raw = mapper.readTree(input);
            var report = provider.normalize(raw,
                    new Indicator("demo.example", "demo.example", IndicatorType.DOMAIN));

            assertThat(report.maliciousCount()).isEqualTo(6);
            assertThat(report.suspiciousCount()).isEqualTo(2);
            assertThat(report.undetectedCount()).isEqualTo(31);
            assertThat(report.tags()).contains("credential-phishing");
            assertThat(report.evidence()).extracting("title")
                    .contains("AlphaSecure", "CloudShield")
                    .doesNotContain("EagleEye");
        }
    }
}
