package com.pedroharo.threatlens.service;

import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.ThreatReport;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class ComparisonService {
    public ChangeSummary compare(RiskAssessment currentAssessment,
                                 List<ProviderReport> currentProviders,
                                 Optional<ThreatReport> previous) {
        if (previous.isEmpty()) return ChangeSummary.firstObservation();

        ThreatReport old = previous.get();
        int scoreDelta = currentAssessment.score() - old.assessment().score();
        int maliciousDelta = totalMalicious(currentProviders) - totalMalicious(old.providers());
        int pulseDelta = totalPulses(currentProviders) - totalPulses(old.providers());
        boolean verdictChanged = currentAssessment.verdict() != old.assessment().verdict();
        List<String> changes = new ArrayList<>();

        if (verdictChanged) {
            changes.add("Verdict changed from " + humanize(old.assessment().verdict().name())
                    + " to " + humanize(currentAssessment.verdict().name()) + ".");
        }
        if (scoreDelta != 0) {
            changes.add("Risk score " + (scoreDelta > 0 ? "increased" : "decreased")
                    + " by " + Math.abs(scoreDelta) + " points.");
        }
        if (maliciousDelta != 0) {
            changes.add("Malicious engine detections " + (maliciousDelta > 0 ? "increased" : "decreased")
                    + " by " + Math.abs(maliciousDelta) + ".");
        }
        if (pulseDelta != 0) {
            changes.add("OTX pulse matches " + (pulseDelta > 0 ? "increased" : "decreased")
                    + " by " + Math.abs(pulseDelta) + ".");
        }
        if (changes.isEmpty()) changes.add("No material change was observed since the previous consultation.");

        return new ChangeSummary(true, old.id(), old.investigatedAt(), scoreDelta,
                maliciousDelta, pulseDelta, verdictChanged, changes.get(0), List.copyOf(changes));
    }

    private static int totalMalicious(List<ProviderReport> reports) {
        return reports.stream().mapToInt(ProviderReport::maliciousCount).sum();
    }

    private static int totalPulses(List<ProviderReport> reports) {
        return reports.stream().mapToInt(ProviderReport::pulseCount).sum();
    }

    private static String humanize(String value) {
        return value.toLowerCase().replace('_', ' ');
    }
}
