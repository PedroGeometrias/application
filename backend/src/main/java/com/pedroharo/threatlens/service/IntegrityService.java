package com.pedroharo.threatlens.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.history.InvestigationRepository;
import com.pedroharo.threatlens.nativecore.NativeCoreService;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
public class IntegrityService {
    private final InvestigationRepository repository;
    private final NativeCoreService nativeCore;
    private final ObjectMapper objectMapper;

    public IntegrityService(InvestigationRepository repository,
                            NativeCoreService nativeCore,
                            ObjectMapper objectMapper) {
        this.repository = repository;
        this.nativeCore = nativeCore;
        this.objectMapper = objectMapper;
    }

    public Result verifyHistory() {
        String expectedPrevious = InvestigationRepository.GENESIS_HASH;
        int checked = 0;
        for (InvestigationRepository.IntegrityRow row : repository.integrityRows()) {
            if (!expectedPrevious.equals(row.previousHash())) {
                return new Result(false, checked, row.id(), expectedPrevious,
                        "The stored previous-hash link does not match the chain.");
            }
            try {
                byte[] payload = objectMapper.writeValueAsBytes(
                        InvestigationService.withIntegrityHash(row.report(), null));
                byte[] prefix = (expectedPrevious + "\n").getBytes(StandardCharsets.UTF_8);
                byte[] combined = new byte[prefix.length + payload.length];
                System.arraycopy(prefix, 0, combined, 0, prefix.length);
                System.arraycopy(payload, 0, combined, prefix.length, payload.length);
                String calculated = nativeCore.hash(combined);
                if (!calculated.equals(row.recordHash())) {
                    return new Result(false, checked, row.id(), expectedPrevious,
                            "The investigation content does not match its integrity hash.");
                }
            } catch (JsonProcessingException exception) {
                return new Result(false, checked, row.id(), expectedPrevious,
                        "The investigation could not be serialized for verification.");
            }
            expectedPrevious = row.recordHash();
            checked++;
        }
        return new Result(true, checked, null, expectedPrevious,
                checked == 0 ? "History is empty." : "All history records and links are intact.");
    }

    public record Result(boolean valid, int checkedRecords, String failedRecordId,
                         String lastValidHash, String message) {}
}
