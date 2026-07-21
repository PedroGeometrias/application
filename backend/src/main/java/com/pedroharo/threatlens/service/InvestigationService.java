package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.ProviderStatus;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.ThreatReport;
import com.pedroharo.threatlens.history.InvestigationRepository;
import com.pedroharo.threatlens.nativecore.NativeCoreService;
import com.pedroharo.threatlens.provider.ThreatProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

@Service
public class InvestigationService {
    private static final Logger log = LoggerFactory.getLogger(InvestigationService.class);

    private final NativeCoreService nativeCore;
    private final List<ThreatProvider> providers;
    private final EvidenceCache cache;
    private final ComparisonService comparisonService;
    private final BriefingService briefingService;
    private final InvestigationRepository repository;
    private final ObjectMapper objectMapper;
    private final Clock clock;

    public InvestigationService(NativeCoreService nativeCore,
                                List<ThreatProvider> providers,
                                EvidenceCache cache,
                                ComparisonService comparisonService,
                                BriefingService briefingService,
                                InvestigationRepository repository,
                                ObjectMapper objectMapper,
                                Clock clock) {
        this.nativeCore = nativeCore;
        this.providers = providers;
        this.cache = cache;
        this.comparisonService = comparisonService;
        this.briefingService = briefingService;
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.clock = clock;
    }

    public ThreatReport investigate(String submitted, boolean forceRefresh) {
        return investigate(nativeCore.classify(submitted), forceRefresh);
    }

    public ThreatReport investigateFile(InputStream file, String originalFilename, boolean forceRefresh) {
        String digest = nativeCore.hash(file);
        Indicator indicator = new Indicator(
                originalFilename == null || originalFilename.isBlank() ? digest : originalFilename,
                digest,
                com.pedroharo.threatlens.domain.IndicatorType.SHA256);
        return investigate(indicator, forceRefresh);
    }

    private ThreatReport investigate(Indicator indicator, boolean forceRefresh) {
        boolean nativeCoreUsed = nativeCore.isAvailable();
        String cacheKey = indicator.type().name() + ":" + indicator.normalized();
        Optional<List<ProviderReport>> cached = forceRefresh ? Optional.empty() : cache.get(cacheKey);
        List<ProviderReport> reports = cached.orElseGet(() -> fetchProviders(indicator));
        if (cached.isEmpty()) cache.put(cacheKey, reports);

        int otxPulses = reports.stream().mapToInt(ProviderReport::pulseCount).sum();
        int vtMalicious = reports.stream().mapToInt(ProviderReport::maliciousCount).sum();
        int vtSuspicious = reports.stream().mapToInt(ProviderReport::suspiciousCount).sum();
        int reputation = reports.stream().filter(ProviderReport::succeeded)
                .mapToInt(ProviderReport::reputation).min().orElse(0);
        int successful = (int) reports.stream().filter(ProviderReport::succeeded).count();
        Instant recencyBoundary = clock.instant().minus(Duration.ofDays(30));
        boolean recent = reports.stream().map(ProviderReport::lastSeen)
                .filter(timestamp -> timestamp != null).anyMatch(timestamp -> timestamp.isAfter(recencyBoundary));
        RiskAssessment assessment = nativeCore.assess(otxPulses, vtMalicious, vtSuspicious,
                reputation, successful, recent);

        Optional<ThreatReport> previous = repository.findLatestByIndicator(indicator.normalized());
        ChangeSummary comparison = comparisonService.compare(assessment, reports, previous);
        BriefingService.Result briefing = briefingService.generate(indicator, assessment, reports, comparison);
        ThreatReport unsigned = new ThreatReport(
                UUID.randomUUID().toString(), indicator, assessment, reports,
                briefing.text(), briefing.source(), comparison, clock.instant(), null,
                nativeCoreUsed, cached.isPresent());
        return persistWithIntegrity(unsigned);
    }

    private List<ProviderReport> fetchProviders(Indicator indicator) {
        List<CompletableFuture<ProviderReport>> futures = providers.stream()
                .filter(provider -> provider.supports(indicator))
                .map(provider -> CompletableFuture.supplyAsync(() -> {
                    try {
                        return provider.investigate(indicator);
                    } catch (Exception exception) {
                        log.error("Provider {} failed unexpectedly", provider.name(), exception);
                        return new ProviderReport(provider.name(), ProviderStatus.UNAVAILABLE,
                                "Provider integration failed: " + exception.getMessage(),
                                0, 0, 0, 0, 0, 0,
                                null, null, null, null, null,
                                List.of(), List.of(), NullNode.getInstance());
                    }
                }))
                .toList();
        List<ProviderReport> reports = new ArrayList<>(futures.size());
        futures.forEach(future -> reports.add(future.join()));
        reports.sort(Comparator.comparingInt(report -> report.provider().contains("OTX") ? 0 : 1));
        return List.copyOf(reports);
    }

    private synchronized ThreatReport persistWithIntegrity(ThreatReport unsigned) {
        String previousHash = repository.latestRecordHash();
        String recordHash;
        try {
            byte[] payload = objectMapper.writeValueAsBytes(unsigned);
            byte[] chainInput = (previousHash + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] combined = new byte[chainInput.length + payload.length];
            System.arraycopy(chainInput, 0, combined, 0, chainInput.length);
            System.arraycopy(payload, 0, combined, chainInput.length, payload.length);
            recordHash = nativeCore.hash(combined);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to create investigation integrity hash", exception);
        }
        ThreatReport report = withIntegrityHash(unsigned, recordHash);
        repository.save(report, previousHash);
        return report;
    }

    public static ThreatReport withIntegrityHash(ThreatReport report, String hash) {
        return new ThreatReport(report.id(), report.indicator(), report.assessment(), report.providers(),
                report.briefing(), report.briefingSource(), report.comparison(), report.investigatedAt(),
                hash, report.nativeCoreUsed(), report.cachedEvidence());
    }
}
