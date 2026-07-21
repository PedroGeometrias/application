package com.pedroharo.threatlens.provider;

import com.fasterxml.jackson.databind.node.NullNode;
import com.pedroharo.threatlens.domain.ProviderReport;
import com.pedroharo.threatlens.domain.ProviderStatus;

import java.util.List;

final class ProviderReports {
    private ProviderReports() {}

    static ProviderReport failure(String provider, ProviderStatus status, String message) {
        return new ProviderReport(provider, status, message,
                0, 0, 0, 0, 0, 0,
                null, null, null, null, null,
                List.of(), List.of(), NullNode.getInstance());
    }
}
