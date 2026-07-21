package com.pedroharo.threatlens.api;

import com.pedroharo.threatlens.domain.HistoryItem;
import com.pedroharo.threatlens.domain.IndicatorType;
import com.pedroharo.threatlens.domain.RiskVerdict;
import com.pedroharo.threatlens.history.InvestigationRepository;
import com.pedroharo.threatlens.service.IntegrityService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/history")
public class HistoryController {
    private final InvestigationRepository repository;
    private final IntegrityService integrityService;

    public HistoryController(InvestigationRepository repository, IntegrityService integrityService) {
        this.repository = repository;
        this.integrityService = integrityService;
    }

    @GetMapping
    public List<HistoryItem> history(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(required = false) IndicatorType type,
            @RequestParam(required = false) RiskVerdict verdict,
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String query) {
        return repository.list(limit, type, verdict, provider, query);
    }

    @GetMapping("/integrity")
    public IntegrityService.Result integrity() {
        return integrityService.verifyHistory();
    }
}
