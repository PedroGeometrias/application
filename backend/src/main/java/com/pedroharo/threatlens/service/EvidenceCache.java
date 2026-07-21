package com.pedroharo.threatlens.service;

import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.domain.ProviderReport;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class EvidenceCache {
    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final ThreatLensProperties properties;
    private final Clock clock;

    public EvidenceCache(ThreatLensProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public Optional<List<ProviderReport>> get(String key) {
        Entry entry = entries.get(key);
        if (entry == null) return Optional.empty();
        if (entry.createdAt.plus(properties.cacheTtl()).isBefore(clock.instant())) {
            entries.remove(key, entry);
            return Optional.empty();
        }
        return Optional.of(entry.reports);
    }

    public void put(String key, List<ProviderReport> reports) {
        entries.put(key, new Entry(List.copyOf(reports), clock.instant()));
    }

    private record Entry(List<ProviderReport> reports, Instant createdAt) {}
}
