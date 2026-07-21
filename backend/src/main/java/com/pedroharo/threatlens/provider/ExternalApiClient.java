package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

@Component
public class ExternalApiClient {
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Duration timeout;

    public ExternalApiClient(HttpClient httpClient,
                             ObjectMapper objectMapper,
                             ThreatLensProperties properties) {
        this.httpClient = httpClient;
        this.objectMapper = objectMapper;
        this.timeout = properties.providers().timeout();
    }

    public ApiResponse get(String url, Map<String, String> headers) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .GET()
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("User-Agent", "ThreatLens/1.0 (+https://github.com/pedrogeometrias)");
        headers.forEach((name, value) -> builder.header(name, value));
        HttpRequest request = builder.build();

        for (int attempt = 0; attempt < 2; ++attempt) {
            try {
                HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                int status = response.statusCode();
                if ((status == 429 || status >= 500) && attempt == 0) {
                    Thread.sleep(500L);
                    continue;
                }
                JsonNode body;
                try {
                    body = response.body().isBlank() ? NullNode.getInstance()
                            : objectMapper.readTree(response.body());
                } catch (IOException ignored) {
                    body = NullNode.getInstance();
                }
                return new ApiResponse(status, body, response.body());
            } catch (IOException exception) {
                if (attempt == 1) {
                    throw new ProviderCallException("Provider request failed", exception);
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new ProviderCallException("Provider request interrupted", exception);
            }
        }
        throw new ProviderCallException("Provider request failed after retry");
    }

    public static String pathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public record ApiResponse(int status, JsonNode body, String rawBody) {}
}
