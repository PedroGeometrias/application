package com.pedroharo.threatlens.history;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pedroharo.threatlens.domain.HistoryItem;
import com.pedroharo.threatlens.domain.IndicatorType;
import com.pedroharo.threatlens.domain.RiskVerdict;
import com.pedroharo.threatlens.domain.ThreatReport;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
public class InvestigationRepository {
    public static final String GENESIS_HASH = "GENESIS";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public InvestigationRepository(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void save(ThreatReport report, String previousHash) {
        String snapshot;
        try {
            snapshot = objectMapper.writeValueAsString(report);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to serialize investigation", exception);
        }

        jdbcTemplate.update("""
                INSERT INTO investigations (
                    id, indicator, normalized_indicator, indicator_type, verdict,
                    risk_score, provider_count, created_at, briefing, snapshot_json,
                    previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                report.id(),
                report.indicator().submitted(),
                report.indicator().normalized(),
                report.indicator().type().name(),
                report.assessment().verdict().name(),
                report.assessment().score(),
                (int) report.providers().stream().filter(provider -> provider.succeeded()).count(),
                report.investigatedAt().toString(),
                report.briefing(),
                snapshot,
                previousHash,
                report.integrityHash());
    }

    public Optional<ThreatReport> findById(String id) {
        List<ThreatReport> reports = jdbcTemplate.query(
                "SELECT snapshot_json FROM investigations WHERE id = ?",
                (rs, row) -> readReport(rs.getString("snapshot_json")), id);
        return reports.stream().findFirst();
    }

    public Optional<ThreatReport> findLatestByIndicator(String normalizedIndicator) {
        List<ThreatReport> reports = jdbcTemplate.query("""
                SELECT snapshot_json FROM investigations
                WHERE normalized_indicator = ?
                ORDER BY rowid DESC LIMIT 1
                """, (rs, row) -> readReport(rs.getString("snapshot_json")), normalizedIndicator);
        return reports.stream().findFirst();
    }

    public String latestRecordHash() {
        List<String> hashes = jdbcTemplate.query(
                "SELECT record_hash FROM investigations ORDER BY rowid DESC LIMIT 1",
                (rs, row) -> rs.getString("record_hash"));
        return hashes.stream().findFirst().orElse(GENESIS_HASH);
    }

    public List<HistoryItem> list(int limit,
                                  IndicatorType type,
                                  RiskVerdict verdict,
                                  String provider,
                                  String query) {
        StringBuilder sql = new StringBuilder("""
                SELECT id, indicator, normalized_indicator, indicator_type, verdict,
                       risk_score, provider_count, created_at, briefing, record_hash
                FROM investigations WHERE 1 = 1
                """);
        List<Object> arguments = new ArrayList<>();
        if (type != null) {
            sql.append(" AND indicator_type = ?");
            arguments.add(type.name());
        }
        if (verdict != null) {
            sql.append(" AND verdict = ?");
            arguments.add(verdict.name());
        }
        if (provider != null && !provider.isBlank()) {
            sql.append(" AND lower(snapshot_json) LIKE ?");
            arguments.add("%\"provider\":\"%" + provider.toLowerCase() + "%\"%");
        }
        if (query != null && !query.isBlank()) {
            sql.append(" AND (lower(indicator) LIKE ? OR lower(normalized_indicator) LIKE ?)");
            String pattern = "%" + query.toLowerCase() + "%";
            arguments.add(pattern);
            arguments.add(pattern);
        }
        sql.append(" ORDER BY rowid DESC LIMIT ?");
        arguments.add(Math.max(1, Math.min(limit, 200)));
        return jdbcTemplate.query(sql.toString(), this::mapHistoryItem, arguments.toArray());
    }

    public List<IntegrityRow> integrityRows() {
        return jdbcTemplate.query("""
                SELECT id, snapshot_json, previous_hash, record_hash
                FROM investigations ORDER BY rowid ASC
                """, (rs, row) -> new IntegrityRow(
                rs.getString("id"),
                readReport(rs.getString("snapshot_json")),
                rs.getString("previous_hash"),
                rs.getString("record_hash")));
    }

    private HistoryItem mapHistoryItem(ResultSet rs, int rowNumber) throws SQLException {
        return new HistoryItem(
                rs.getString("id"),
                rs.getString("indicator"),
                rs.getString("normalized_indicator"),
                IndicatorType.valueOf(rs.getString("indicator_type")),
                RiskVerdict.valueOf(rs.getString("verdict")),
                rs.getInt("risk_score"),
                rs.getInt("provider_count"),
                Instant.parse(rs.getString("created_at")),
                rs.getString("briefing"),
                rs.getString("record_hash"));
    }

    private ThreatReport readReport(String json) {
        try {
            return objectMapper.readValue(json, ThreatReport.class);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Stored investigation is malformed", exception);
        }
    }

    public record IntegrityRow(String id, ThreatReport report, String previousHash, String recordHash) {}
}
