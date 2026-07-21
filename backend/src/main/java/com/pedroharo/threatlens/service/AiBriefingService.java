package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AiBriefingService {
    private static final Logger log = LoggerFactory.getLogger(AiBriefingService.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ThreatLensProperties properties;

    public AiBriefingService(HttpClient httpClient,
                             ObjectMapper objectMapper,
                             ThreatLensProperties properties) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    public String generate(Indicator indicator,
                           RiskAssessment assessment,
                           List<ProviderReport> providers,
                           ChangeSummary comparison) {
        if (!properties.ai().enabled() || properties.ai().apiKey().isBlank()) return null;

        try {
            Map<String, Object> compact = new LinkedHashMap<>();
            compact.put("indicator", indicator);
            compact.put("assessment", assessment);
            compact.put("providers", providers.stream().map(provider -> Map.of(
                    "name", provider.provider(),
                    "status", provider.status(),
                    "malicious", provider.maliciousCount(),
                    "suspicious", provider.suspiciousCount(),
                    "pulses", provider.pulseCount(),
                    "reputation", provider.reputation(),
                    "tags", provider.tags(),
                    "message", provider.message()
            )).toList());
            compact.put("change", comparison);

            ObjectNode requestBody = objectMapper.createObjectNode();
            requestBody.put("model", properties.ai().model());
            requestBody.put("instructions", "You are a careful threat-intelligence analyst. Write one concise client briefing in plain language using only the supplied normalized evidence. Never call an indicator safe; say 'no known threat detected' when signals are zero. Distinguish evidence from recommended follow-up. Do not add markdown, headings, or facts not in the data.");
            requestBody.put("input", objectMapper.writeValueAsString(compact));
            requestBody.put("max_output_tokens", 260);
            requestBody.put("store", false);

            HttpRequest request = HttpRequest.newBuilder(
                            URI.create(properties.ai().baseUrl() + "/v1/responses"))
                    .timeout(properties.ai().timeout())
                    .header("Authorization", "Bearer " + properties.ai().apiKey())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            objectMapper.writeValueAsString(requestBody), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = httpClient.send(request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                log.warn("AI briefing provider returned HTTP {}", response.statusCode());
                return null;
            }
            JsonNode root = objectMapper.readTree(response.body());
            for (JsonNode output : root.path("output")) {
                for (JsonNode content : output.path("content")) {
                    if ("output_text".equals(content.path("type").asText())) {
                        String text = content.path("text").asText("").trim();
                        if (!text.isBlank()) return text;
                    }
                }
            }
        } catch (Exception exception) {
            if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("AI briefing failed; deterministic briefing will be used", exception);
        }
        return null;
    }
}
