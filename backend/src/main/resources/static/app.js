const state = { current: null, status: null };

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

document.addEventListener('DOMContentLoaded', () => {
    bindTabs();
    bindSearch();
    bindHistory();
    bindVerification();
    loadStatus();
    loadHistory();
});

function bindTabs() {
    $$('.query-tab').forEach(tab => tab.addEventListener('click', () => {
        const indicator = tab.id === 'indicator-tab';
        $$('.query-tab').forEach(item => {
            const selected = item === tab;
            item.classList.toggle('active', selected);
            item.setAttribute('aria-selected', String(selected));
        });
        $('#indicator-panel').hidden = !indicator;
        $('#file-panel').hidden = indicator;
    }));
}

function bindSearch() {
    $('#search-form').addEventListener('submit', async event => {
        event.preventDefault();
        const value = $('#indicator-input').value.trim();
        if (!value) return;
        await runIndicator(value, false);
    });

    $$('[data-example]').forEach(button => button.addEventListener('click', () => {
        $('#indicator-input').value = button.dataset.example;
        $('#indicator-tab').click();
        runIndicator(button.dataset.example, false);
    }));

    const fileInput = $('#file-input');
    const dropZone = $('#drop-zone');
    fileInput.addEventListener('change', () => updateFileLabel(fileInput.files[0]));
    ['dragenter', 'dragover'].forEach(type => dropZone.addEventListener(type, event => {
        event.preventDefault();
        dropZone.classList.add('dragging');
    }));
    ['dragleave', 'drop'].forEach(type => dropZone.addEventListener(type, event => {
        event.preventDefault();
        dropZone.classList.remove('dragging');
    }));
    dropZone.addEventListener('drop', event => {
        if (!event.dataTransfer.files.length) return;
        fileInput.files = event.dataTransfer.files;
        updateFileLabel(fileInput.files[0]);
    });
    $('#file-form').addEventListener('submit', async event => {
        event.preventDefault();
        const file = fileInput.files[0];
        if (!file) return showActivity('Choose a file first.', 'error');
        const data = new FormData();
        data.append('file', file);
        setBusy(true, `Hashing ${file.name} with the C backend, then checking its SHA-256 digest…`);
        try {
            const report = await api('/api/investigations/file', { method: 'POST', body: data });
            renderReport(report);
            await loadHistory();
            showActivity(`The backend hashed the file with C. Only SHA-256 ${report.indicator.normalized} was sent to intelligence providers.`, 'success');
        } catch (error) {
            showActivity(error.message, 'error');
        } finally {
            setBusy(false);
        }
    });

    $('#refresh-result').addEventListener('click', () => {
        if (state.current) runIndicator(state.current.indicator.normalized, true);
    });
    $('#export-report').addEventListener('click', () => {
        if (state.current) window.location.assign(`/api/investigations/${encodeURIComponent(state.current.id)}/export`);
    });
}

async function runIndicator(value, forceRefresh) {
    setBusy(true, forceRefresh ? 'Refreshing provider evidence…' : 'Correlating OTX and VirusTotal evidence…');
    try {
        const report = await api('/api/investigations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value, forceRefresh })
        });
        renderReport(report);
        await loadHistory();
        showActivity(report.cachedEvidence
            ? 'Investigation completed from the protected short-term provider cache.'
            : 'Investigation completed and added to the local integrity chain.', 'success');
    } catch (error) {
        showActivity(error.message, 'error');
    } finally {
        setBusy(false);
    }
}

async function loadStatus() {
    try {
        state.status = await api('/api/status');
        const capabilities = [
            ['C core', state.status.nativeCore],
            ['OTX', state.status.otxConfigured],
            ['VirusTotal', state.status.virusTotalConfigured],
            ['AI brief', state.status.aiBriefing],
            ['Signing', state.status.reportSigning]
        ];
        $('#system-status').innerHTML = capabilities.map(([label, enabled]) =>
            `<span class="status-pill ${enabled ? 'ok' : 'off'}">${escapeHtml(label)}</span>`).join('');
        $('#demo-banner').hidden = !state.status.demoMode;
    } catch (error) {
        $('#system-status').innerHTML = '<span class="status-pill off">Status unavailable</span>';
    }
}

function renderReport(report) {
    state.current = report;
    const assessment = report.assessment;
    const totals = totalProviderStats(report.providers);
    const resultShell = $('#result-shell');
    resultShell.hidden = false;

    $('#result-type').textContent = report.indicator.type;
    $('#result-time').textContent = formatDate(report.investigatedAt);
    $('#result-title').textContent = report.indicator.normalized;
    $('#result-subtitle').textContent = report.indicator.submitted === report.indicator.normalized
        ? `Investigation ID ${report.id}`
        : `Submitted as ${report.indicator.submitted} · Investigation ID ${report.id}`;

    const color = assessment.verdict === 'HIGH_RISK' ? 'var(--danger)'
        : assessment.verdict === 'SUSPICIOUS' ? 'var(--warning)'
            : assessment.verdict === 'NO_KNOWN_THREAT' ? 'var(--safe)' : 'var(--faint)';
    $('#risk-dial').style.setProperty('--score', assessment.score);
    $('#risk-dial').style.setProperty('--dial', color);
    $('#risk-score').textContent = assessment.score;
    $('#risk-verdict').textContent = humanize(assessment.verdict);
    $('#risk-verdict').style.color = color;
    $('#reason-list').innerHTML = assessment.reasons.map(reason =>
        `<span class="reason-chip">${escapeHtml(humanize(reason))}</span>`).join('');

    $('#briefing-source').textContent = report.briefingSource;
    $('#briefing-text').textContent = report.briefing;
    renderMetrics(totals, report.providers);
    renderComparison(report.comparison);
    renderProviders(report.providers);
    renderEvidence(report.providers);
    $('#raw-json').textContent = JSON.stringify(Object.fromEntries(
        report.providers.map(provider => [provider.provider, provider.raw])), null, 2);
    $('#integrity-hash').textContent = report.integrityHash;
    $('#integrity-hash').title = report.integrityHash;
    $('#native-note').textContent = report.nativeCoreUsed ? 'C core active' : 'Java fallback used';

    resultShell.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderMetrics(totals, providers) {
    const successful = providers.filter(provider => provider.status === 'SUCCESS').length;
    const reputation = providers.filter(provider => provider.status === 'SUCCESS')
        .reduce((lowest, provider) => Math.min(lowest, provider.reputation), 0);
    const cards = [
        ['Malicious', totals.malicious, 'engine detections', totals.malicious ? 'alert' : 'good'],
        ['Suspicious', totals.suspicious, 'engine results', totals.suspicious ? 'warn' : 'good'],
        ['OTX pulses', totals.pulses, 'community matches', totals.pulses ? 'warn' : 'good'],
        ['Reputation', reputation, 'lowest source score', reputation < 0 ? 'alert' : 'good'],
        ['Sources', `${successful}/${providers.length}`, 'usable responses', successful === providers.length ? 'good' : 'warn']
    ];
    $('#metric-grid').innerHTML = cards.map(([label, value, detail, tone]) => `
        <article class="metric-card ${tone}">
            <span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail)}</small>
        </article>`).join('');
}

function renderComparison(comparison) {
    $('#change-summary').textContent = comparison.summary;
    const changes = comparison.changes || [];
    $('#change-list').innerHTML = changes.map(change => `<li>${escapeHtml(change)}</li>`).join('');
    $('#change-list').hidden = changes.length === 0;
}

function renderProviders(providers) {
    $('#provider-grid').innerHTML = providers.map(provider => {
        const short = provider.provider.includes('OTX') ? 'OTX' : 'VT';
        const lastSeen = provider.lastSeen ? formatDate(provider.lastSeen, true) : '—';
        const metrics = provider.provider.includes('OTX')
            ? [['Pulses', provider.pulseCount], ['Reputation', provider.reputation], ['Country', provider.country || '—'], ['Last seen', lastSeen]]
            : [['Malicious', provider.maliciousCount], ['Suspicious', provider.suspiciousCount], ['Undetected', provider.undetectedCount], ['Last seen', lastSeen]];
        return `<article class="provider-card panel">
            <div class="provider-header">
                <div class="provider-name"><span class="provider-icon">${short}</span><div><h3>${escapeHtml(provider.provider)}</h3><small>${escapeHtml(provider.networkOwner || provider.asn || 'Threat-intelligence source')}</small></div></div>
                <span class="provider-status ${provider.status.toLowerCase().replaceAll('_', '-')}">${escapeHtml(humanize(provider.status))}</span>
            </div>
            <p class="provider-message">${escapeHtml(provider.message)}</p>
            <div class="provider-metrics">${metrics.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join('')}</div>
            <div class="tag-list">${provider.tags.slice(0, 10).map(tag => `<span class="tag">${escapeHtml(tag)}</span>`).join('')}</div>
        </article>`;
    }).join('');
}

function renderEvidence(providers) {
    const evidence = providers.flatMap(provider => provider.evidence || []);
    $('#evidence-count').textContent = `${evidence.length} item${evidence.length === 1 ? '' : 's'}`;
    $('#empty-evidence').hidden = evidence.length !== 0;
    $('#evidence-body').innerHTML = evidence.map(item => {
        const reference = state.status?.demoMode ? null : safeUrl(item.reference);
        return `<tr>
        <td><span class="severity ${item.severity.toLowerCase()}">${escapeHtml(item.severity)}</span></td>
        <td>${escapeHtml(item.source)}</td>
        <td>${reference ? `<a class="evidence-link" href="${escapeHtml(reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)} ↗</a>` : escapeHtml(item.title)}</td>
        <td>${escapeHtml(item.detail)}</td>
    </tr>`;
    }).join('');
}

function bindHistory() {
    $('#history-filters').addEventListener('submit', event => {
        event.preventDefault();
        loadHistory(new FormData(event.currentTarget));
    });
    $('#verify-history').addEventListener('click', async () => {
        const button = $('#verify-history');
        button.disabled = true;
        try {
            const result = await api('/api/history/integrity');
            showActivity(`${result.valid ? 'Integrity verified.' : 'Integrity check failed.'} ${result.message} Checked ${result.checkedRecords} record(s).`, result.valid ? 'success' : 'error');
        } catch (error) {
            showActivity(error.message, 'error');
        } finally {
            button.disabled = false;
        }
    });
}

async function loadHistory(formData = null) {
    const params = new URLSearchParams();
    if (formData) {
        for (const [key, value] of formData.entries()) if (value) params.set(key, value);
    }
    try {
        const items = await api(`/api/history?${params.toString()}`);
        $('#history-empty').hidden = items.length !== 0;
        $('#history-list').innerHTML = items.map(item => `
            <button class="history-item" type="button" data-history-id="${escapeHtml(item.id)}">
                <span class="history-score">${item.riskScore}</span>
                <span class="history-copy"><strong>${escapeHtml(item.normalizedIndicator)}</strong><small>${escapeHtml(item.indicatorType)} · ${item.providerCount} source${item.providerCount === 1 ? '' : 's'}</small></span>
                <span class="history-verdict ${item.verdict.toLowerCase().replaceAll('_', '-')}">${escapeHtml(humanize(item.verdict))}</span>
                <span class="history-meta">${formatDate(item.createdAt, true)}</span>
            </button>`).join('');
        $$('[data-history-id]').forEach(button => button.addEventListener('click', async () => {
            try {
                renderReport(await api(`/api/investigations/${encodeURIComponent(button.dataset.historyId)}`));
            } catch (error) {
                showActivity(error.message, 'error');
            }
        }));
    } catch (error) {
        showActivity(`History unavailable: ${error.message}`, 'error');
    }
}

function bindVerification() {
    const dialog = $('#verify-dialog');
    $('#verify-export').addEventListener('click', () => {
        $('#verify-result').hidden = true;
        dialog.showModal();
    });
    $('#run-verification').addEventListener('click', async () => {
        const file = $('#verify-file').files[0];
        const resultBox = $('#verify-result');
        if (!file) {
            resultBox.textContent = 'Choose an exported JSON report first.';
            resultBox.className = 'verify-result invalid';
            resultBox.hidden = false;
            return;
        }
        try {
            const envelope = JSON.parse(await file.text());
            if (!envelope.payload || !envelope.signature) throw new Error('This file has no signed payload.');
            const result = await api('/api/reports/verify', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: envelope.payload, signature: envelope.signature })
            });
            resultBox.textContent = result.message;
            resultBox.className = `verify-result ${result.valid ? 'valid' : 'invalid'}`;
            resultBox.hidden = false;
        } catch (error) {
            resultBox.textContent = error.message;
            resultBox.className = 'verify-result invalid';
            resultBox.hidden = false;
        }
    });
}

function setBusy(busy, message = '') {
    $$('.primary-button, #refresh-result').forEach(button => button.disabled = busy);
    if (busy) showActivity(message, 'loading');
}

function showActivity(message, type) {
    const box = $('#activity-message');
    box.textContent = message;
    box.className = `activity-message ${type || ''}`;
    box.hidden = false;
}

function updateFileLabel(file) {
    if (!file) return;
    $('#drop-zone strong').textContent = file.name;
    $('#drop-zone small').textContent = `${formatBytes(file.size)} · ready for SHA-256`;
}

async function api(url, options = {}) {
    const response = await fetch(url, options);
    const contentType = response.headers.get('content-type') || '';
    const body = contentType.includes('application/json') ? await response.json() : await response.text();
    if (!response.ok) throw new Error(body?.message || body || `Request failed with HTTP ${response.status}`);
    return body;
}

function totalProviderStats(providers) {
    return providers.reduce((totals, provider) => ({
        malicious: totals.malicious + provider.maliciousCount,
        suspicious: totals.suspicious + provider.suspiciousCount,
        pulses: totals.pulses + provider.pulseCount
    }), { malicious: 0, suspicious: 0, pulses: 0 });
}

function humanize(value) {
    return String(value ?? '').toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, character => character.toUpperCase());
}

function formatDate(value, compact = false) {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return 'Unknown time';
    return new Intl.DateTimeFormat(undefined, compact
        ? { dateStyle: 'medium', timeStyle: 'short' }
        : { dateStyle: 'long', timeStyle: 'short' }).format(date);
}

function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
}

function safeUrl(value) {
    if (!value) return null;
    try {
        const url = new URL(value);
        return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
    } catch { return null; }
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>'"]/g, character => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;'
    })[character]);
}
