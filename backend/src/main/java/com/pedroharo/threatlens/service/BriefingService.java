package com.pedroharo.threatlens.service;

import com.pedroharo.threatlens.domain.ChangeSummary;
import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.RiskAssessment;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class BriefingService {
    private final DeterministicBriefingService deterministic;
    private final AiBriefingService ai;

    public BriefingService(DeterministicBriefingService deterministic, AiBriefingService ai) {
        this.deterministic = deterministic;
        this.ai = ai;
    }

    public Result generate(Indicator indicator,
                           RiskAssessment assessment,
                           List<ProviderReport> providers,
                           ChangeSummary comparison) {
        String aiBriefing = ai.generate(indicator, assessment, providers, comparison);
        if (aiBriefing != null) return new Result(aiBriefing, "OpenAI");
        return new Result(deterministic.generate(indicator, assessment, providers, comparison),
                "Deterministic");
    }

    public record Result(String text, String source) {}
}
