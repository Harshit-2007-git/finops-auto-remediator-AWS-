// ==========================================================================
// FinOps Auto-Remediation Cloud Console - Frontend Logic
// Supports Mock Simulation & Live Real AWS Accounts (Hardened & Sanitized)
// ==========================================================================

let currentFindings = [];
let currentAuditLogs = [];
let auditViewMode = 'decrypted'; // 'decrypted' or 'ciphertext'
let activeMode = 'mock'; // 'mock' or 'real'
let csrfToken = '';
let currentAuditIndex = null;

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

async function fetchCsrfToken() {
    try {
        const res = await fetch('/api/csrf-token');
        const data = await res.json();
        if (data.csrf_token) {
            csrfToken = data.csrf_token;
        }
    } catch (err) {
        console.warn('Could not fetch CSRF token:', err);
    }
}

async function apiPost(url, payload = {}) {
    if (!csrfToken) {
        await fetchCsrfToken();
    }
    return await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-FinOps-Token': csrfToken
        },
        body: JSON.stringify(payload)
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initEventListeners();
    await fetchCsrfToken();
    fetchSystemStatus();
    fetchFindings();
    fetchAuditLogs();
});

// --------------------------------------------------------------------------
// Navigation & Tabs
// --------------------------------------------------------------------------
function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-tab');

            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetContent = document.getElementById(targetId);
            if (targetContent) targetContent.classList.add('active');
        });
    });
}

function initEventListeners() {
    // Top Bar Actions
    document.getElementById('btnRunScan').addEventListener('click', handleRunScan);
    document.getElementById('btnSeed').addEventListener('click', handleSeedResources);
    document.getElementById('btnAutoRemediateAll').addEventListener('click', handleAutoRemediateAll);

    // Event delegation for table action buttons (Avoids inline onclick vulnerabilities)
    document.getElementById('findingsTableBody').addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-approve-action');
        if (btn) {
            const { resourceId, action, token, expires } = btn.dataset;
            handleApproveResource(resourceId, action, token, expires);
        }
    });

    document.getElementById('auditTableBody').addEventListener('click', (e) => {
        const btn = e.target.closest('.btn-inspect-audit');
        if (btn) {
            const index = parseInt(btn.dataset.index, 10);
            openAuditModal(index);
        }
    });

    // Autopilot Toggle
    const autopilotToggle = document.getElementById('autopilotToggle');
    if (autopilotToggle) {
        autopilotToggle.addEventListener('change', async (e) => {
            const isEnabled = e.target.checked;
            const statusPill = document.getElementById('autopilotStatus');
            statusPill.textContent = isEnabled ? 'ON' : 'OFF';
            statusPill.className = `status-pill ${isEnabled ? 'active' : ''}`;

            try {
                await apiPost('/api/autopilot', { enabled: isEnabled });
                showToast(`Autopilot ${isEnabled ? 'Enabled (Auto-scanning background thread)' : 'Disabled'}`, 'info');
            } catch (err) {
                showToast('Failed to toggle autopilot: ' + err.message, 'error');
            }
        });
    }

    // Dry Run Toggle
    const dryRunToggle = document.getElementById('dryRunToggle');
    dryRunToggle.addEventListener('change', (e) => {
        const isDryRun = e.target.checked;
        const statusPill = document.getElementById('dryRunStatus');
        statusPill.textContent = isDryRun ? 'ENABLED' : 'DISABLED';
        statusPill.className = `status-pill ${isDryRun ? 'active' : ''}`;
        
        apiPost('/api/config', { dry_run: isDryRun }).then(() => {
            showToast(`Dry Run Mode ${isDryRun ? 'Enabled (Safe Simulation)' : 'Disabled (Live State Changes)'}`, isDryRun ? 'info' : 'warning');
        });
    });

    // Audit View Mode Toggle
    const btnDecrypted = document.getElementById('btnViewDecrypted');
    const btnCiphertext = document.getElementById('btnViewCiphertext');

    btnDecrypted.addEventListener('click', () => {
        auditViewMode = 'decrypted';
        btnDecrypted.classList.add('active');
        btnCiphertext.classList.remove('active');
        renderAuditLogs();
        if (document.getElementById('detailModal').classList.contains('show') && currentAuditIndex !== null) {
            openAuditModal(currentAuditIndex);
        }
    });

    btnCiphertext.addEventListener('click', () => {
        auditViewMode = 'ciphertext';
        btnCiphertext.classList.add('active');
        btnDecrypted.classList.remove('active');
        renderAuditLogs();
        if (document.getElementById('detailModal').classList.contains('show') && currentAuditIndex !== null) {
            openAuditModal(currentAuditIndex);
        }
    });

    // Modal Close
    window.addEventListener('click', (e) => {
        const detailModal = document.getElementById('detailModal');
        const awsModal = document.getElementById('awsModal');
        if (e.target === detailModal) closeModal();
        if (e.target === awsModal) closeAwsModal();
    });
}

// --------------------------------------------------------------------------
// Real AWS Account Linking Modal & Handlers
// --------------------------------------------------------------------------
function openAwsModal() {
    document.getElementById('awsModal').classList.add('show');
}

function closeAwsModal() {
    document.getElementById('awsModal').classList.remove('show');
}

async function handleOnboardTenant() {
    const tenantName = document.getElementById('inputOnboardTenantName').value.trim() || 'PixelForge Studios';
    const tenantId = tenantName.toLowerCase().replace(/[^a-z0-9_-]/g, '-').replace(/-+/g, '-');

    try {
        const res = await apiPost('/api/aws/onboard', { tenant_name: tenantName, tenant_id: tenantId });
        const data = await res.json();
        if (data.status === 'SUCCESS') {
            const resultBox = document.getElementById('onboardResultBox');
            resultBox.style.display = 'block';
            document.getElementById('onboardPlatformAccount').textContent = data.platform_account_id;
            document.getElementById('onboardExternalId').textContent = data.external_id;

            // Pre-fill Step 2 form
            document.getElementById('inputConnectTenantId').value = data.tenant_id;
            document.getElementById('inputExternalId').value = data.external_id;

            showToast(`Generated Onboarding Package for ${tenantName}!`, 'success');
        } else {
            showToast(`Onboarding failed: ${data.message}`, 'error');
        }
    } catch (err) {
        showToast(`Onboarding error: ${err.message}`, 'error');
    }
}

function handleScopeChange() {
    const scope = document.getElementById('selectScope').value;
    const warning = document.getElementById('scopeAllWarning');
    if (warning) {
        warning.style.display = (scope === 'all') ? 'block' : 'none';
    }
}

function toggleAuthFields() {
    const method = document.querySelector('input[name="authMethod"]:checked').value;
    const roleFields = document.getElementById('roleFields');
    if (roleFields) {
        roleFields.style.display = (method === 'role') ? 'block' : 'none';
    }
}

function toggleKmsFields() {
    const kmsOption = document.querySelector('input[name="kmsOption"]:checked')?.value;
    const byokFields = document.getElementById('byokKeyFields');
    if (byokFields) {
        byokFields.style.display = (kmsOption === 'byok') ? 'block' : 'none';
    }
}

function getCredentialsPayload() {
    const method = document.querySelector('input[name="authMethod"]:checked').value;
    const region = document.getElementById('selectRegion').value;
    const scope_mode = document.getElementById('selectScope').value;
    const isScopeAll = (scope_mode === 'all');
    const dry_run = isScopeAll ? true : document.getElementById('dryRunToggle').checked;
    const kms_option = document.querySelector('input[name="kmsOption"]:checked')?.value || 'platform';
    const byok_key_arn = document.getElementById('inputByokKeyArn')?.value?.trim() || '';

    const payload = {
        auth_method: method,
        region,
        scope_mode,
        dry_run,
        kms_option,
        byok_key_arn,
    };

    if (method === 'role') {
        payload.tenant_id = document.getElementById('inputConnectTenantId').value.trim() || 'pixelforge';
        payload.role_arn = document.getElementById('inputRoleArn').value.trim();
        payload.external_id = document.getElementById('inputExternalId').value.trim();
        payload.remediation_role_arn = document.getElementById('inputRemediationRoleArn').value.trim();
    }

    return payload;
}

async function testAwsConnection() {
    const feedback = document.getElementById('awsConnectionFeedback');
    feedback.style.display = 'block';
    feedback.className = 'connection-feedback';
    feedback.textContent = 'Verifying cross-account role & least-privilege permissions...';

    const payload = getCredentialsPayload();

    try {
        const res = await apiPost('/api/aws/test-connection', payload);
        const data = await res.json();

        if (data.status === 'SUCCESS') {
            feedback.className = 'connection-feedback success';
            feedback.replaceChildren();
            const strong = document.createElement('strong');
            strong.textContent = data.account_id;
            const code = document.createElement('code');
            code.textContent = data.arn;
            feedback.append(
                '✓ Verified! Connected to AWS Account: ',
                strong,
                document.createElement('br'),
                'Assumed Role: ',
                code,
                ` (Region: ${data.region})`,
                document.createElement('br'),
                '✓ Least-Privilege Self-Check Passed (iam:ListUsers denied as expected)'
            );
        } else {
            feedback.className = 'connection-feedback error';
            feedback.textContent = `✕ Connection Failed: ${data.message || 'Unknown error'}`;
        }
    } catch (err) {
        feedback.className = 'connection-feedback error';
        feedback.textContent = `✕ Network error: ${err.message}`;
    }
}

async function connectAwsAccount() {
    const payload = getCredentialsPayload();
    showToast('Connecting to real AWS account...', 'info');

    try {
        const res = await apiPost('/api/aws/connect', payload);
        const data = await res.json();

        if (data.status === 'SUCCESS') {
            closeAwsModal();
            showToast(`Connected to Real AWS Account: ${data.account_id}`, 'success');
            await fetchSystemStatus();
            await fetchFindings();
            await fetchAuditLogs();
        } else {
            showToast(`Failed to connect: ${data.message}`, 'error');
        }
    } catch (err) {
        showToast('Connection error: ' + err.message, 'error');
    }
}

async function disconnectRealAws() {
    try {
        const res = await apiPost('/api/aws/disconnect', {});
        const data = await res.json();
        closeAwsModal();
        showToast('Switched back to Mock Simulation mode', 'info');
        await fetchSystemStatus();
        await fetchFindings();
        await fetchAuditLogs();
    } catch (err) {
        showToast('Error resetting mode: ' + err.message, 'error');
    }
}

// --------------------------------------------------------------------------
// API Calls & Data Fetching
// --------------------------------------------------------------------------
async function fetchSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        activeMode = data.mode;

        // Header and Banner
        const connectionPill = document.getElementById('connectionPill');
        const connectionText = document.getElementById('connectionText');
        const regionText = document.getElementById('currentRegionText');
        const realBanner = document.getElementById('realAwsBanner');
        const btnSeed = document.getElementById('btnSeed');

        regionText.textContent = data.region;

        if (data.mode === 'real') {
            connectionPill.className = 'connection-badge real';
            connectionText.replaceChildren();
            const strong = document.createElement('strong');
            strong.textContent = data.account_id;
            connectionText.append('LIVE AWS: ', strong);

            realBanner.style.display = 'flex';
            document.getElementById('bannerAccountId').textContent = data.account_id;
            document.getElementById('bannerRegion').textContent = data.region;
            document.getElementById('bannerArn').textContent = data.caller_arn;
            btnSeed.style.display = 'none'; // Seeding disabled on real AWS
        } else {
            connectionPill.className = 'connection-badge mock';
            connectionText.replaceChildren();
            const strong = document.createElement('strong');
            strong.textContent = 'Simulation (Mock)';
            connectionText.append('Mode: ', strong);

            realBanner.style.display = 'none';
            btnSeed.style.display = 'inline-flex';
        }

        // Stats
        document.getElementById('statMonthlySavings').textContent = `$${data.total_savings_monthly.toFixed(2)}`;
        const realizedElem = document.getElementById('statRealizedSavings');
        if (realizedElem) realizedElem.textContent = `$${(data.realized_savings_monthly || 0).toFixed(2)}`;
        document.getElementById('statFlaggedCount').textContent = data.flagged_count;
        document.getElementById('statEc2Count').textContent = data.ec2_count;
        document.getElementById('statEbsCount').textContent = data.ebs_count;
        document.getElementById('statRemediatedCount').textContent = data.remediated_count;
        const simElem = document.getElementById('statSimulatedActions');
        if (simElem) simElem.textContent = data.simulated_actions_count || 0;
        const realActElem = document.getElementById('statRealActions');
        if (realActElem) realActElem.textContent = data.real_actions_count || 0;
        document.getElementById('statEscalatedCount').textContent = data.escalated_count;

        const dryRunToggle = document.getElementById('dryRunToggle');
        dryRunToggle.checked = data.dry_run;
        const statusPill = document.getElementById('dryRunStatus');
        statusPill.textContent = data.dry_run ? 'ENABLED' : 'DISABLED';
        statusPill.className = `status-pill ${data.dry_run ? 'active' : ''}`;

        if (data.csrf_token) {
            csrfToken = data.csrf_token;
        }

        const autoToggle = document.getElementById('autopilotToggle');
        if (autoToggle) {
            autoToggle.checked = !!data.autopilot_enabled;
            const autoStatus = document.getElementById('autopilotStatus');
            if (autoStatus) {
                autoStatus.textContent = data.autopilot_enabled ? 'ON' : 'OFF';
                autoStatus.className = `status-pill ${data.autopilot_enabled ? 'active' : ''}`;
            }
        }
    } catch (err) {
        console.error('Failed to fetch status:', err);
    }
}

async function fetchFindings() {
    try {
        const res = await fetch('/api/findings');
        const data = await res.json();
        currentFindings = data.findings || [];
        renderFindings();
    } catch (err) {
        console.error('Failed to fetch findings:', err);
    }
}

async function fetchAuditLogs() {
    try {
        const res = await fetch('/api/audit-logs');
        const data = await res.json();
        currentAuditLogs = data.logs || [];
        renderAuditLogs();
    } catch (err) {
        console.error('Failed to fetch audit logs:', err);
    }
}

async function handleRunScan() {
    const btn = document.getElementById('btnRunScan');
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-icon">⏳</span> Scanning...`;

    try {
        const res = await apiPost('/api/scan', {});
        const result = await res.json();
        showToast(`Scan complete: Found ${result.findings.length} waste resources`, 'success');
        await fetchSystemStatus();
        await fetchFindings();
        await fetchAuditLogs();
    } catch (err) {
        showToast('Scan failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">▶</span> Run Scheduled Scan`;
    }
}

async function handleSeedResources() {
    if (!confirm('Are you sure you want to reset the environment to the canonical 8 demo resources? This wipes simulation state and re-seeds cleanly.')) {
        return;
    }
    const btn = document.getElementById('btnSeed');
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-icon">⏳</span> Resetting...`;

    try {
        const res = await apiPost('/api/seed', {});
        const result = await res.json();
        showToast(result.message || 'Demo infrastructure reset to 8 canonical resources!', 'success');
        await fetchSystemStatus();
        await fetchFindings();
        await fetchAuditLogs();
    } catch (err) {
        showToast('Failed to reset demo resources: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">↺</span> Reset Demo Cloud`;
    }
}

async function handleAutoRemediateAll() {
    const btn = document.getElementById('btnAutoRemediateAll');
    btn.disabled = true;
    try {
        const res = await apiPost('/api/retry-failed', {});
        const result = await res.json();
        showToast(`Retry complete: ${result.retried_count} retried, ${result.succeeded_count} succeeded`, 'info');
        await fetchSystemStatus();
        await fetchFindings();
        await fetchAuditLogs();
    } catch (err) {
        showToast('Failed to retry actions: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

async function handleApproveResource(resourceId, action, token, expires) {
    try {
        const res = await apiPost('/api/approve-action', {
            resource_id: resourceId,
            action,
            token,
            expires
        });
        const result = await res.json();
        if (result.status === 'SUCCESS') {
            showToast(`Approved & Executed: ${resourceId} ${action}`, 'success');
        } else {
            showToast(`Approval failed: ${result.message}`, 'error');
        }
        await fetchSystemStatus();
        await fetchFindings();
        await fetchAuditLogs();
    } catch (err) {
        showToast('Approval request error: ' + err.message, 'error');
    }
}

// --------------------------------------------------------------------------
// Rendering Logic
// --------------------------------------------------------------------------
function renderFindings() {
    const tbody = document.getElementById('findingsTableBody');
    const badgeCount = document.getElementById('findingsCountBadge');
    badgeCount.textContent = currentFindings.length;

    if (!currentFindings.length) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="12">
                    <div class="empty-state">
                        <span class="empty-icon">☁</span>
                        <p>No waste findings detected in this account. Click <strong>"Run Scheduled Scan"</strong> to inspect resources.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = currentFindings.map(item => {
        const f = item.finding;
        const ev = item.evaluation;
        const env = (f.tags && f.tags.env) ? f.tags.env.toLowerCase() : 'unknown';
        const owner = (f.tags && f.tags.owner) ? f.tags.owner : 'unassigned';
        const typeClass = f.resource_type === 'ec2' ? 'badge-ec2' : 'badge-ebs';
        const envClass = env === 'prod' ? 'badge-prod' : (env === 'qa' ? 'badge-qa' : 'badge-dev');

        let decisionBadge = '';
        if (ev.decision === 'AUTO_REMEDIATE') decisionBadge = `<span class="badge badge-action-auto">AUTO_REMEDIATE</span>`;
        else if (ev.decision === 'ESCALATE') decisionBadge = `<span class="badge badge-action-esc">ESCALATE</span>`;
        else decisionBadge = `<span class="badge badge-action-log">LOG_ONLY</span>`;

        let actionCell = '-';
        if (item.remediation_status === 'AUTO_REMEDIATED') {
            actionCell = `<span class="text-success" style="font-size: 11px; font-weight:700;">✓ Remediated</span>`;
        } else if (item.remediation_status === 'HUMAN_APPROVED_REMEDIATED') {
            actionCell = `<span class="text-success" style="font-size: 11px; font-weight:700;">✓ Approved & Done</span>`;
        } else if (item.remediation_status === 'CIRCUIT_BREAKER_TRIPPED') {
            actionCell = `<span style="color: #F59E0B; font-size: 11px; font-weight:600;">⏸ Tripped (Limit)</span>`;
        } else if (ev.decision === 'ESCALATE' && item.approval_token) {
            actionCell = `<button class="action-btn-sm action-btn-approve btn-approve-action" data-resource-id="${escapeHtml(f.resource_id)}" data-action="${escapeHtml(item.action_type || 'STOP')}" data-token="${escapeHtml(item.approval_token)}" data-expires="${escapeHtml(String(item.expires_epoch))}">✓ Approve</button>`;
        } else if (ev.decision === 'AUTO_REMEDIATE') {
            actionCell = `<span class="text-success" style="font-size: 11px; font-weight:600;">Eligible</span>`;
        }

        const reasonText = item.why_no_auto_action || ev.reason || '-';

        return `
            <tr>
                <td class="mono-cell">${escapeHtml(f.resource_id)}</td>
                <td><span class="badge ${escapeHtml(typeClass)}">${escapeHtml(f.resource_type.toUpperCase())}</span></td>
                <td><span class="badge ${escapeHtml(envClass)}">${escapeHtml(env.toUpperCase())}</span></td>
                <td style="color: #94A3B8; font-size: 12px;">${escapeHtml(owner)}</td>
                <td>${f.idle_duration_hours.toFixed(1)} hrs</td>
                <td>${f.avg_cpu !== null ? f.avg_cpu.toFixed(1) + '%' : 'N/A'}</td>
                <td style="font-weight: 700; color: #F8FAFC;">$${f.estimated_monthly_cost.toFixed(2)}</td>
                <td><span class="badge ${ev.confidence === 'HIGH' ? 'badge-conf-high' : 'badge-conf-low'}">${escapeHtml(ev.confidence)}</span></td>
                <td><span class="badge ${ev.risk === 'HIGH' ? 'badge-risk-high' : 'badge-risk-low'}">${escapeHtml(ev.risk)}</span></td>
                <td>${decisionBadge}</td>
                <td style="font-size: 11px; color: #CBD5E1; max-width: 220px;">${escapeHtml(reasonText)}</td>
                <td>${actionCell}</td>
            </tr>`;
    }).join('');
}

function renderAuditLogs() {
    const tbody = document.getElementById('auditTableBody');
    const badgeCount = document.getElementById('auditCountBadge');
    badgeCount.textContent = currentAuditLogs.length;

    if (!currentAuditLogs.length) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="6">
                    <div class="empty-state">
                        <span class="empty-icon">🔒</span>
                        <p>No audit records yet. Run a scan or execute remediations to inspect KMS envelope encryption.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = currentAuditLogs.map((log, index) => {
        const shortLogId = log.log_id ? log.log_id.substring(0, 8) + '...' : 'unknown';
        const dateStr = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '-';
        const kmsAlias = log.kms_key_alias || 'alias/finops-key';

        let inspectBtn = `<button class="btn btn-secondary btn-inspect-audit" style="padding: 4px 10px; font-size: 11px;" data-index="${index}">👁 Inspect</button>`;

        let payloadSnippet = '';
        if (auditViewMode === 'decrypted') {
            payloadSnippet = `<span style="font-size:12px; color:#A7F3D0;">🔒 KMS Envelope (Inspect to Decrypt)</span>`;
        } else {
            const rawCipher = (log.envelope && log.envelope.ciphertext_b64) ? log.envelope.ciphertext_b64.substring(0, 24) + '...' : '[Encrypted AES-256 Blob]';
            payloadSnippet = `<span class="mono-cell" style="color:#CBD5E1;">${escapeHtml(rawCipher)}</span>`;
        }

        return `
            <tr>
                <td class="mono-cell" title="${escapeHtml(log.log_id)}">${escapeHtml(shortLogId)}</td>
                <td style="font-size: 12px; color: #94A3B8;">${escapeHtml(dateStr)}</td>
                <td class="mono-cell">${escapeHtml(log.resource_id)}</td>
                <td><span class="badge badge-action-auto">${escapeHtml(log.action_taken)}</span></td>
                <td style="font-size: 11px; color: #38BDF8;">${escapeHtml(kmsAlias)}</td>
                <td>
                    <div style="display:flex; align-items:center; justify-content:space-between; gap:12px;">
                        ${payloadSnippet}
                        ${inspectBtn}
                    </div>
                </td>
            </tr>`;
    }).join('');
}

async function openAuditModal(index) {
    currentAuditIndex = index;
    const log = currentAuditLogs[index];
    if (!log) return;

    const modal = document.getElementById('detailModal');
    const title = document.getElementById('modalTitle');
    const content = document.getElementById('modalJsonContent');

    title.textContent = `Audit Record: ${log.log_id}`;

    if (auditViewMode === 'ciphertext') {
        const displayData = {
            mode: "RAW_KMS_ENVELOPE_ENCRYPTED",
            log_id: log.log_id,
            tenant_id: log.tenant_id,
            run_id: log.run_id,
            kms_key_id: log.envelope?.kms_key_id || log.kms_key_alias || "alias/finops-key",
            ciphertext_b64: log.envelope?.ciphertext_b64,
            encrypted_data_key_b64: log.envelope?.encrypted_data_key_b64,
            nonce_b64: log.envelope?.nonce_b64,
            encryption_context: log.envelope?.encryption_context
        };
        content.textContent = JSON.stringify(displayData, null, 2);
        modal.classList.add('show');
    } else {
        content.textContent = "Decrypting audit envelope via AWS KMS (calling kms:Decrypt)...";
        modal.classList.add('show');

        try {
            const res = await apiPost('/api/audit-logs/decrypt', {
                log_id: log.log_id,
                envelope: log.envelope,
                as_auditor: true,
                tenant_id: log.tenant_id || 'pixelforge'
            });
            const data = await res.json();
            if (data.status === 'SUCCESS') {
                const displayData = {
                    mode: "AUTHENTIC_KMS_DECRYPTED_PAYLOAD",
                    kms_operation: "kms:Decrypt(encrypted_data_key, context) -> AES-256-GCM.decrypt(nonce, ciphertext)",
                    log_id: log.log_id,
                    tenant_id: log.tenant_id,
                    run_id: log.run_id,
                    timestamp: log.timestamp,
                    resource_id: log.resource_id,
                    action_taken: log.action_taken,
                    company: log.company,
                    decrypted_details: data.decrypted_details
                };
                content.textContent = JSON.stringify(displayData, null, 2);
            } else {
                content.textContent = JSON.stringify({
                    mode: "DECRYPTION_FAILED",
                    log_id: log.log_id,
                    error: data.message || "Failed to decrypt with AWS KMS"
                }, null, 2);
            }
        } catch (err) {
            content.textContent = `Error calling KMS Decrypt endpoint: ${err.message}`;
        }
    }
}

function closeModal() {
    document.getElementById('detailModal').classList.remove('show');
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const span = document.createElement('span');
    span.textContent = message;
    toast.appendChild(span);
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}
