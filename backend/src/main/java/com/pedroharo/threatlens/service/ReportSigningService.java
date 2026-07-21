package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.api.ResourceNotFoundException;
import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.ThreatReport;
import com.pedroharo.threatlens.history.InvestigationRepository;
import com.pedroharo.threatlens.nativecore.NativeCoreService;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

@Service
public class ReportSigningService {
    private final ThreatLensProperties properties;
    private final NativeCoreService nativeCore;
    private final InvestigationRepository repository;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public ReportSigningService(ThreatLensProperties properties,
                                NativeCoreService nativeCore,
                                InvestigationRepository repository,
                                ObjectMapper objectMapper,
                                Clock clock) {
        this.properties = properties;
        this.nativeCore = nativeCore;
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public ExportEnvelope export(String id) {
        ThreatReport report = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Investigation not found: " + id));
        JsonNode payload = objectMapper.valueToTree(report);
        byte[] canonical = bytes(payload);
        String payloadHash = nativeCore.hash(canonical);
        String canonicalBase64 = Base64.getEncoder().encodeToString(canonical);

        if (!signingAvailable()) {
            return new ExportEnvelope(payload, payloadHash, canonicalBase64, false, null, null, null,
                    clock.instant(), "Signing is unavailable; the report is still protected by its history-chain hash.");
        }
        String signature = nativeCore.sign(canonical);
        return new ExportEnvelope(payload, payloadHash, canonicalBase64, true, "RSA-PSS-SHA256", signature,
                readPublicKey(), clock.instant(), null);
    }

    public boolean verify(JsonNode payload, String signature) {
        if (!signingAvailable() || payload == null || signature == null || signature.isBlank()) return false;
        return nativeCore.verify(bytes(payload), signature);
    }

    public boolean signingAvailable() {
        return properties.signing().enabled()
                && nativeCore.isAvailable()
                && Files.isRegularFile(Path.of(properties.signing().privateKeyPath()))
                && Files.isRegularFile(Path.of(properties.signing().publicKeyPath()));
    }

    public String readPublicKey() {
        try {
            return Files.readString(Path.of(properties.signing().publicKeyPath()), StandardCharsets.US_ASCII);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read report-signing public key", exception);
        }
    }

    private byte[] bytes(JsonNode payload) {
        try {
            return objectMapper.writeValueAsBytes(payload);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to serialize signed report", exception);
        }
    }

    public record ExportEnvelope(
            JsonNode payload,
            String payloadSha256,
            String payloadCanonicalBase64,
            boolean signed,
            String algorithm,
            String signature,
            String publicKey,
            Instant exportedAt,
            String note
    ) {}
}
