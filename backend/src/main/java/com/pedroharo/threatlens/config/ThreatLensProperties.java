package com.pedroharo.threatlens.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "threatlens")
public record ThreatLensProperties(
        boolean demoMode,
        Duration cacheTtl,
        NativeCore nativeCore,
        Providers providers,
        Ai ai,
        Signing signing
) {
    public record NativeCore(String path, boolean required, Duration timeout) {}

    public record Providers(Otx otx, VirusTotal virusTotal, Duration timeout) {
        public record Otx(String baseUrl, String apiKey) {}
        public record VirusTotal(String baseUrl, String apiKey) {}
    }

    public record Ai(boolean enabled, String baseUrl, String apiKey, String model, Duration timeout) {}

    public record Signing(boolean enabled, String privateKeyPath, String publicKeyPath) {}
}
