package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.EvidenceItem;
import com.pedroharo.threatlens.domain.EvidenceSeverity;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.ProviderStatus;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class VirusTotalProvider implements ThreatProvider {
    private final ExternalApiClient client;
    private final ObjectMapper objectMapper;
    private final ThreatLensProperties properties;

    public VirusTotalProvider(ExternalApiClient client,
                              ObjectMapper objectMapper,
                              ThreatLensProperties properties) {
        this.client = client;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    @Override
    public String name() {
        return "VirusTotal";
    }

    @Override
    public boolean supports(Indicator indicator) {
        return true;
    }

    @Override
    public ProviderReport investigate(Indicator indicator) {
        if (properties.demoMode()) {
            return normalize(loadFixture("fixtures/virustotal-demo.json"), indicator);
        }
        String apiKey = properties.providers().virusTotal().apiKey();
        if (apiKey.isBlank()) {
            return ProviderReports.failure(name(), ProviderStatus.SKIPPED,
                    "VirusTotal is disabled because VT_API_KEY is not configured.");
        }

        String resource = switch (indicator.type()) {
            case IPV4, IPV6 -> "ip_addresses";
            case DOMAIN -> "domains";
            case MD5, SHA1, SHA256 -> "files";
        };
        String url = properties.providers().virusTotal().baseUrl()
                + "/api/v3/" + resource + "/"
                + ExternalApiClient.pathSegment(indicator.normalized());

        try {
            ExternalApiClient.ApiResponse response = client.get(url, Map.of("x-apikey", apiKey));
            if (response.status() == 200) return normalize(response.body(), indicator);
            if (response.status() == 404) {
                return ProviderReports.failure(name(), ProviderStatus.NOT_FOUND,
                        "VirusTotal has no report for this indicator.");
            }
            if (response.status() == 429) {
                return ProviderReports.failure(name(), ProviderStatus.RATE_LIMITED,
                        "VirusTotal request quota was reached. Try again later.");
            }
            return ProviderReports.failure(name(), ProviderStatus.UNAVAILABLE,
                    "VirusTotal returned HTTP " + response.status() + ".");
        } catch (ProviderCallException exception) {
            return ProviderReports.failure(name(), ProviderStatus.UNAVAILABLE,
                    "VirusTotal could not be reached: " + exception.getMessage());
        }
    }

    ProviderReport normalize(JsonNode root, Indicator indicator) {
        JsonNode attributes = root.path("data").path("attributes");
        JsonNode statistics = attributes.path("last_analysis_stats");
        int malicious = statistics.path("malicious").asInt(0);
        int suspicious = statistics.path("suspicious").asInt(0);
        int harmless = statistics.path("harmless").asInt(0);
        int undetected = statistics.path("undetected").asInt(0);
        int reputation = attributes.path("reputation").asInt(0);
        Set<String> tags = new LinkedHashSet<>();
        attributes.path("tags").forEach(tag -> tags.add(tag.asText()));
        String suggestedLabel = attributes.path("popular_threat_classification")
                .path("suggested_threat_label").asText("");
        if (!suggestedLabel.isBlank()) tags.add(suggestedLabel);

        List<EvidenceItem> evidence = new ArrayList<>();
        JsonNode engines = attributes.path("last_analysis_results");
        if (engines.isObject()) {
            engines.fields().forEachRemaining(entry -> {
                if (evidence.size() >= 15) return;
                JsonNode engine = entry.getValue();
                String category = engine.path("category").asText("");
                if (!"malicious".equals(category) && !"suspicious".equals(category)) return;
                String engineName = engine.path("engine_name").asText(entry.getKey());
                String detection = engine.path("result").asText("Threat signal");
                evidence.add(new EvidenceItem(name(),
                        "malicious".equals(category) ? EvidenceSeverity.HIGH : EvidenceSeverity.MEDIUM,
                        "Detection engine", engineName, detection, null));
            });
        }

        String country = textOrNull(attributes, "country");
        String asn = attributes.hasNonNull("asn") ? "AS" + attributes.path("asn").asText() : null;
        String owner = textOrNull(attributes, "as_owner");
        Instant firstSeen = epoch(attributes,
                indicator.type() == com.pedroharo.threatlens.domain.IndicatorType.DOMAIN
                        ? "creation_date" : "first_submission_date");
        Instant lastSeen = epoch(attributes, "last_analysis_date");
        if (lastSeen == null) lastSeen = epoch(attributes, "last_modification_date");
        String message = malicious == 0 && suspicious == 0
                ? "No VirusTotal engine currently marks this indicator malicious or suspicious."
                : malicious + " malicious and " + suspicious + " suspicious engine result"
                        + (malicious + suspicious == 1 ? "" : "s") + ".";

        return new ProviderReport(name(), ProviderStatus.SUCCESS, message,
                malicious, suspicious, harmless, undetected, 0, reputation,
                country, asn, owner, firstSeen, lastSeen,
                List.copyOf(tags), List.copyOf(evidence), root);
    }

    private JsonNode loadFixture(String path) {
        try (var input = new ClassPathResource(path).getInputStream()) {
            return objectMapper.readTree(input);
        } catch (IOException exception) {
            throw new ProviderCallException("Demo VirusTotal fixture could not be loaded", exception);
        }
    }

    private static String textOrNull(JsonNode node, String field) {
        String value = node.path(field).asText("");
        return value.isBlank() ? null : value;
    }

    private static Instant epoch(JsonNode node, String field) {
        long value = node.path(field).asLong(0);
        return value > 0 ? Instant.ofEpochSecond(value) : null;
    }
}
