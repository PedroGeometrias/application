package com.pedroharo.threatlens.provider;

import com.pedroharo.threatlens.domain.Indicator;
import com.pedroharo.threatlens.domain.ProviderReport;

public interface ThreatProvider {
    String name();
    boolean supports(Indicator indicator);
    ProviderReport investigate(Indicator indicator);
}
