package com.pedroharo.threatlens.service;

import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import com.pedroharo.threatlens.domain.RiskVerdict;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DeterministicBriefingService {
    public String generate(Indicator indicator,
                           RiskAssessment assessment,
                           List<ProviderReport> providers,
                           ChangeSummary comparison) {
        int malicious = providers.stream().mapToInt(ProviderReport::maliciousCount).sum();
        int suspicious = providers.stream().mapToInt(ProviderReport::suspiciousCount).sum();
        int pulses = providers.stream().mapToInt(ProviderReport::pulseCount).sum();
        long successful = providers.stream().filter(ProviderReport::succeeded).count();

        StringBuilder briefing = new StringBuilder();
        briefing.append("The ").append(humanType(indicator)).append(" was assessed as ")
                .append(humanVerdict(assessment.verdict())).append(" with a risk score of ")
                .append(assessment.score()).append("/100. ");

        if (successful == 0) {
            briefing.append("No threat-intelligence provider returned usable evidence, so the result is inconclusive. ");
        } else if (malicious + suspicious + pulses == 0) {
            briefing.append("The available sources returned no current malicious-engine, suspicious-engine, or OTX pulse matches. ")
                    .append("This means no known threat was detected; it does not prove that the indicator is safe. ");
        } else {
            briefing.append("Evidence includes ").append(malicious).append(" malicious engine detection")
                    .append(malicious == 1 ? "" : "s").append(", ")
                    .append(suspicious).append(" suspicious result")
                    .append(suspicious == 1 ? "" : "s").append(", and ")
                    .append(pulses).append(" OTX threat pulse match")
                    .append(pulses == 1 ? "" : "es").append(". ");
        }

        if (comparison.previousAvailable()) {
            briefing.append(comparison.summary()).append(' ');
        }

        briefing.append(switch (assessment.verdict()) {
            case HIGH_RISK -> "Consider blocking or isolating the indicator after confirming business context, and investigate related activity.";
            case SUSPICIOUS -> "Validate the indicator against internal telemetry and business context before deciding whether to block it.";
            case NO_KNOWN_THREAT -> "Continue normal monitoring and reassess if new telemetry or user reports emerge.";
            case INCONCLUSIVE -> "Retry the lookup when provider access is available and avoid making a allow/block decision from this result alone.";
        });
        return briefing.toString();
    }

    private static String humanType(Indicator indicator) {
        return switch (indicator.type()) {
            case IPV4, IPV6 -> "IP address " + indicator.normalized();
            case DOMAIN -> "domain " + indicator.normalized();
            case MD5, SHA1, SHA256 -> "file hash " + indicator.normalized();
        };
    }

    private static String humanVerdict(RiskVerdict verdict) {
        return switch (verdict) {
            case HIGH_RISK -> "high risk";
            case SUSPICIOUS -> "suspicious";
            case NO_KNOWN_THREAT -> "no known threat detected";
            case INCONCLUSIVE -> "inconclusive";
        };
    }
}
