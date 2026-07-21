package com.pedroharo.threatlens.api;

import com.pedroharo.threatlens.config.ThreatLensProperties;
import com.pedroharo.threatlens.nativecore.NativeCoreService;
import com.pedroharo.threatlens.service.ReportSigningService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/status")
public class StatusController {
    private final ThreatLensProperties properties;
    private final NativeCoreService nativeCore;
    private final ReportSigningService signingService;

    public StatusController(ThreatLensProperties properties,
                            NativeCoreService nativeCore,
                            ReportSigningService signingService) {
        this.properties = properties;
        this.nativeCore = nativeCore;
        this.signingService = signingService;
    }

    @GetMapping
    public Map<String, Object> status() {
        return Map.of(
                "demoMode", properties.demoMode(),
                "nativeCore", nativeCore.isAvailable(),
                "otxConfigured", properties.demoMode() || !properties.providers().otx().apiKey().isBlank(),
                "virusTotalConfigured", properties.demoMode()
                        || !properties.providers().virusTotal().apiKey().isBlank(),
                "aiBriefing", properties.ai().enabled() && !properties.ai().apiKey().isBlank(),
                "reportSigning", signingService.signingAvailable()
        );
    }
}
