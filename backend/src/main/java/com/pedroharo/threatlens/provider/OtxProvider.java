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
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class OtxProvider implements ThreatProvider {
    private final ExternalApiClient client;
    private final ObjectMapper objectMapper;
    private final ThreatLensProperties properties;

    public OtxProvider(ExternalApiClient client,
                       ObjectMapper objectMapper,
                       ThreatLensProperties properties) {
        this.client = client;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    @Override
    public String name() {
        return "AlienVault OTX";
    }

    @Override
    public boolean supports(Indicator indicator) {
        return true;
    }

    @Override
    public ProviderReport investigate(Indicator indicator) {
        if (properties.demoMode()) {
            return normalize(loadFixture("fixtures/otx-demo.json"), indicator);
        }

        String type = switch (indicator.type()) {
            case IPV4 -> "IPv4";
            case IPV6 -> "IPv6";
            case DOMAIN -> "domain";
            case MD5, SHA1, SHA256 -> "file";
        };
        String url = properties.providers().otx().baseUrl()
                + "/api/v1/indicators/" + type + "/"
                + ExternalApiClient.pathSegment(indicator.normalized()) + "/general";
        Map<String, String> headers = properties.providers().otx().apiKey().isBlank()
                ? Map.of()
                : Map.of("X-OTX-API-KEY", properties.providers().otx().apiKey());

        try {
            ExternalApiClient.ApiResponse response = client.get(url, headers);
            if (response.status() == 200) return normalize(response.body(), indicator);
            if (response.status() == 404) {
                return ProviderReports.failure(name(), ProviderStatus.NOT_FOUND,
                        "OTX has no record for this indicator.");
            }
            if (response.status() == 429) {
                return ProviderReports.failure(name(), ProviderStatus.RATE_LIMITED,
                        "OTX request quota was reached. Try again later.");
            }
            return ProviderReports.failure(name(), ProviderStatus.UNAVAILABLE,
                    "OTX returned HTTP " + response.status() + ".");
        } catch (ProviderCallException exception) {
            return ProviderReports.failure(name(), ProviderStatus.UNAVAILABLE,
                    "OTX could not be reached: " + exception.getMessage());
        }
    }

    ProviderReport normalize(JsonNode root, Indicator indicator) {
        JsonNode pulseInfo = root.path("pulse_info");
        JsonNode pulses = pulseInfo.path("pulses");
        int pulseCount = pulseInfo.path("count").asInt(pulses.isArray() ? pulses.size() : 0);
        int reputation = root.path("reputation").asInt(0);
        Set<String> tags = new LinkedHashSet<>();
        List<EvidenceItem> evidence = new ArrayList<>();
        List<Instant> timestamps = new ArrayList<>();

        if (pulses.isArray()) {
            for (JsonNode pulse : pulses) {
                pulse.path("tags").forEach(tag -> tags.add(tag.asText()));
                addInstant(timestamps, pulse.path("created").asText(null));
                addInstant(timestamps, pulse.path("modified").asText(null));
                if (evidence.size() < 12) {
                    String title = pulse.path("name").asText("OTX threat pulse");
                    String adversary = pulse.path("adversary").asText("");
                    String detail = adversary.isBlank()
                            ? pulse.path("description").asText("Community threat-intelligence match.")
                            : "Associated adversary: " + adversary;
                    String pulseId = pulse.path("id").asText("");
                    String reference = pulseId.isBlank() ? null
                            : "https://otx.alienvault.com/pulse/" + pulseId;
                    evidence.add(new EvidenceItem(name(), EvidenceSeverity.HIGH,
                            "Threat pulse", title, abbreviate(detail, 260), reference));
                }
            }
        }

        String country = firstText(root, "country_name", "country_code", "country");
        String asn = firstText(root, "asn", "asn_name");
        String owner = firstText(root, "as_owner", "organization", "whois");
        timestamps.sort(Comparator.naturalOrder());
        Instant firstSeen = timestamps.isEmpty() ? null : timestamps.get(0);
        Instant lastSeen = timestamps.isEmpty() ? null : timestamps.get(timestamps.size() - 1);
        String message = pulseCount == 0
                ? "No OTX threat pulses currently reference this indicator."
                : pulseCount + " OTX threat pulse" + (pulseCount == 1 ? "" : "s")
                        + " reference this indicator.";

        return new ProviderReport(name(), ProviderStatus.SUCCESS, message,
                0, 0, 0, 0, pulseCount, reputation,
                country, asn, owner, firstSeen, lastSeen,
                List.copyOf(tags), List.copyOf(evidence), root);
    }

    private JsonNode loadFixture(String path) {
        try (var input = new ClassPathResource(path).getInputStream()) {
            return objectMapper.readTree(input);
        } catch (IOException exception) {
            throw new ProviderCallException("Demo OTX fixture could not be loaded", exception);
        }
    }

    private static String firstText(JsonNode node, String... fields) {
        for (String field : fields) {
            String value = node.path(field).asText("");
            if (!value.isBlank() && !"null".equalsIgnoreCase(value)) return value;
        }
        return null;
    }

    private static void addInstant(List<Instant> destination, String value) {
        if (value == null || value.isBlank()) return;
        try {
            destination.add(Instant.parse(value));
        } catch (DateTimeParseException ignored) {
            // Provider timestamps are best-effort context.
        }
    }

    private static String abbreviate(String value, int maximum) {
        if (value == null || value.length() <= maximum) return value;
        return value.substring(0, maximum - 1) + "…";
    }
}
