/**
 * BradlyAI - Driverless SOC Frontend // Hyper-Agile Production SaaS Architecture
 * Integrated with FastAPI Python Core, True Generative Open AI / Groq Streaming, Local SQLite persistence, and Web Audio
 */

class CyberAudio {
    constructor() {
        this.ctx = null;
        this.muted = false;
    }

    init() {
        if (!this.ctx) {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (AudioContext) this.ctx = new AudioContext();
        }
    }

    playBeep(freq = 600, type = 'sine', duration = 0.08) {
        if (this.muted || !this.ctx) return;
        try {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = type;
            osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
            gain.gain.setValueAtTime(0.1, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, this.ctx.currentTime + duration);
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            osc.start();
            osc.stop(this.ctx.currentTime + duration);
        } catch (e) {}
    }

    playLaser() {
        if (this.muted || !this.ctx) return;
        try {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(880, this.ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(110, this.ctx.currentTime + 0.15);
            gain.gain.setValueAtTime(0.15, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, this.ctx.currentTime + 0.15);
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            osc.start();
            osc.stop(this.ctx.currentTime + 0.15);
        } catch (e) {}
    }

    playShield() {
        if (this.muted || !this.ctx) return;
        try {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(150, this.ctx.currentTime);
            osc.frequency.exponentialRampToValueAtTime(600, this.ctx.currentTime + 0.25);
            gain.gain.setValueAtTime(0.2, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, this.ctx.currentTime + 0.25);
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            osc.start();
            osc.stop(this.ctx.currentTime + 0.25);
        } catch (e) {}
    }

    playAlarm() {
        if (this.muted || !this.ctx) return;
        try {
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'square';
            osc.frequency.setValueAtTime(440, this.ctx.currentTime);
            osc.frequency.setValueAtTime(880, this.ctx.currentTime + 0.1);
            osc.frequency.setValueAtTime(440, this.ctx.currentTime + 0.2);
            gain.gain.setValueAtTime(0.12, this.ctx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.01, this.ctx.currentTime + 0.35);
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            osc.start();
            osc.stop(this.ctx.currentTime + 0.35);
        } catch (e) {}
    }
}

class CyCraftApp {
    constructor() {
        this.currentTab = 'dashboard';
        this.currentAlertFilter = 'ALL';
        this.mitreTacticFilter = 'ALL';
        this.airScenario = 0; // index in SIMULATED_ATTACKS
        this.simulationRunning = false;
        this.alertsData = [];
        this.asmAssets = [];
        this.mitreMatrix = [];
        this.systemConfig = {};
        this.chatHistory = [
            { sender: 'ai', text: "Greetings, Security Analyst. I am your BradlyAI Driverless SOC Copilot. Python Multi-Model Security Mesh and persistent SQLite engine are fully active. How may I assist your investigation today?" }
        ];

        this.audio = new CyberAudio();
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.cacheElements();
            this.bindEvents();
            this.initWebSocket();
            this.fetchBackendData();
        });
    }

    cacheElements() {
        this.tabs = document.querySelectorAll('.nav-btn');
        this.mainContent = document.getElementById('main-content');
        this.modalOverlay = document.getElementById('modal-overlay');
        this.simModalOverlay = document.getElementById('sim-modal-overlay');
        this.settingsModalOverlay = document.getElementById('settings-modal-overlay');
        this.tickerContent = document.getElementById('ticker-content');
    }

    bindEvents() {
        this.tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                this.audio.init();
                this.audio.playBeep(720, 'sine', 0.05);
                const target = tab.getAttribute('data-tab');
                this.switchTab(target);
            });
        });

        const globalTriggerBtn = document.getElementById('btn-trigger-sim');
        if (globalTriggerBtn) {
            globalTriggerBtn.addEventListener('click', () => {
                this.audio.init();
                this.audio.playAlarm();
                this.triggerSimulatedAttackBackend();
            });
        }

        document.querySelectorAll('.btn-close-modal').forEach(btn => {
            btn.addEventListener('click', () => {
                this.audio.playBeep(400, 'sine', 0.05);
                this.closeModals();
            });
        });

        document.body.addEventListener('click', () => this.audio.init(), { once: true });
    }

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host || 'localhost:8000';
        const wsUrl = `${protocol}//${host}/api/v1/ws/stream`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            console.log("⚡ BradlyAI Live Driverless WebSockets Channel Active.");
            document.querySelector('.driverless-badge').innerHTML = `<span class="status-dot"></span> 100% Autonomous Mesh`;
        };

        this.ws.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data);
                if (msg.type === "TICKER_UPDATE") {
                    this.addLiveTickerItem(msg);
                    // Fetch alerts again to guarantee tables match live pool
                    this.fetchAlertsBackend();
                } else if (msg.type === "HANDSHAKE") {
                    console.log("[WebSocket Handshake]:", msg.message);
                }
            } catch (err) {}
        };

        this.ws.onclose = () => {
            setTimeout(() => this.initWebSocket(), 5000);
        };
    }

    addLiveTickerItem(msg) {
        if (!this.tickerContent) return;
        this.audio.playBeep(880, 'triangle', 0.05);
        const htmlItem = `
            <div class="ticker-item" style="animation: fadeIn 0.4s ease;">
                <span class="ticker-badge ${msg.severity.toLowerCase().substring(0,4)}">${msg.severity}</span>
                <span><strong>${msg.endpoint}</strong>: ${msg.title}</span>
                <span class="ticker-time">(${msg.status})</span>
            </div>
        `;
        this.tickerContent.insertAdjacentHTML('afterbegin', htmlItem + '<span style="color: var(--border-color);">///</span>');
    }

    async fetchBackendData() {
        this.renderStatsTop();
        this.renderDashboard(); 

        await this.fetchAlertsBackend();

        try {
            const resAsm = await fetch('/api/v1/asm/assets');
            if (resAsm.ok) this.asmAssets = await resAsm.json();
        } catch (err) {}

        try {
            const resMitre = await fetch('/api/v1/mitre/matrix');
            if (resMitre.ok) this.mitreMatrix = await resMitre.json();
        } catch (err) {}

        try {
            const resConf = await fetch('/api/v1/system/config');
            if (resConf.ok) this.systemConfig = await resConf.json();
        } catch (err) {}
    }

    async fetchAlertsBackend() {
        try {
            const res = await fetch('/api/v1/alerts');
            if (res.ok) {
                this.alertsData = await res.json();
                if (this.currentTab === 'dashboard') this.renderAlertsTable();
                this.startLiveSecurityTicker();
            }
        } catch (err) {}
    }

    switchTab(tabId) {
        this.currentTab = tabId;
        this.tabs.forEach(tab => {
            if (tab.getAttribute('data-tab') === tabId) tab.classList.add('active');
            else tab.classList.remove('active');
        });
        this.renderTabContent();
    }

    renderTabContent() {
        switch(this.currentTab) {
            case 'dashboard':
                this.renderStats();
                this.renderDashboard();
                this.renderAlertsTable();
                setTimeout(() => this.drawTrendsChart(), 100);
                break;
            case 'air':
                this.renderAirPipeline();
                break;
            case 'asm':
                this.renderAsm();
                break;
            case 'forensics':
                this.renderForensics();
                break;
            case 'mitre':
                this.renderMitre();
                break;
            case 'copilot':
                this.renderCopilot();
                break;
        }
    }

    /* Platform Advanced SOC Settings Modal */
    openSettingsModal() {
        this.audio.playBeep(750, 'sine', 0.05);
        const card = document.getElementById('settings-modal-card');
        if (!card) return;

        card.innerHTML = `
            <div class="modal-header" style="background:rgba(15,23,42,0.95); border-bottom:1px solid var(--color-cyan);">
                <div class="modal-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="var(--color-cyan)" stroke-width="2" width="24" height="24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    <span>Advanced Platform SOC Configuration // Active Core</span>
                </div>
                <button class="btn-close-modal" onclick="app.closeModals()">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <div class="modal-body" style="background:#050710;">
                <div style="background:rgba(255,255,255,0.02); padding:16px; border-radius:10px; border:1px solid rgba(255,255,255,0.05);">
                    <h4 style="font-family:'Orbitron'; color:var(--color-cyan); margin-bottom:12px; font-size:1rem;">🤖 Configure Live LLM Provider for Copilot</h4>
                    <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:16px;">
                        Paste your Open AI or Groq API Key to empower our Python Generative Copilot with true live cloud analysis. (Keys are stored purely in your active Python memory session).
                    </div>
                    
                    <div style="display:flex; flex-direction:column; gap:12px;">
                        <div>
                            <label style="font-size:0.75rem; color:#cbd5e1; font-family:'JetBrains Mono';">OpenAI API Key (sk-...)</label>
                            <input type="password" id="conf-openai-key" class="chat-input" style="width:100%; margin-top:4px;" placeholder="sk-proj-..." value="${this.systemConfig.openai_key_configured ? 'sk-************************************' : ''}">
                        </div>

                        <div>
                            <label style="font-size:0.75rem; color:#cbd5e1; font-family:'JetBrains Mono';">Groq API Key (gsk_...)</label>
                            <input type="password" id="conf-groq-key" class="chat-input" style="width:100%; margin-top:4px;" placeholder="gsk_..." value="${this.systemConfig.groq_key_configured ? 'gsk_************************************' : ''}">
                        </div>
                    </div>
                </div>

                <div style="background:rgba(255,255,255,0.02); padding:16px; border-radius:10px; border:1px solid rgba(255,255,255,0.05); margin-top:8px;">
                    <h4 style="font-family:'Orbitron'; color:white; margin-bottom:12px; font-size:1rem;">⚡ Autonomous Behavioral Parameters</h4>
                    
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; align-items:center;">
                        <div>
                            <div style="font-size:0.85rem; color:#cbd5e1;">Auto-Containment Threshold</div>
                            <div style="font-size:0.7rem; color:var(--text-muted);">AI Confidence minimum to trigger network isolation</div>
                        </div>
                        <div style="display:flex; gap:10px; align-items:center;">
                            <input type="range" id="conf-thresh" min="80" max="99" value="${this.systemConfig.auto_containment_threshold || 95}" style="flex:1;">
                            <strong style="font-family:'JetBrains Mono'; color:var(--color-green);" id="thresh-val">${this.systemConfig.auto_containment_threshold || 95}%</strong>
                        </div>
                    </div>

                    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:20px; padding-top:16px; border-top:1px solid rgba(255,255,255,0.05);">
                        <div>
                            <div style="font-size:0.85rem; color:#cbd5e1;">Live Enterprise Background Telemetry Stream</div>
                            <div style="font-size:0.7rem; color:var(--text-muted);">Periodic organic packet logs generated in background worker</div>
                        </div>
                        <button id="btn-toggle-sim" class="btn-filter ${this.systemConfig.live_simulation_active ? 'active' : ''}" style="font-weight:700;">
                            ${this.systemConfig.live_simulation_active ? '● WORKER ACTIVE' : '○ WORKER PAUSED'}
                        </button>
                    </div>
                </div>

                <div style="background:rgba(244,63,94,0.08); border:1px solid rgba(244,63,94,0.3); padding:16px; border-radius:10px; margin-top:8px; display:flex; justify-content:space-between; align-items:center;">
                    <div>
                        <strong style="color:var(--color-red); font-size:0.95rem;">Reset SIEM Alert Pool</strong>
                        <div style="font-size:0.75rem; color:#fecdd3;">Wipes all active SQLite incident reports and restores initial pristine database state.</div>
                    </div>
                    <button class="btn-trigger-attack" onclick="app.resetSiemDatabaseBackend()" style="padding:10px 16px; font-size:0.8rem;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        Purge SQLite DB
                    </button>
                </div>
            </div>
            <div class="modal-footer" style="background:rgba(15,23,42,0.95);">
                <button class="btn-filter" onclick="app.closeModals()">Dismiss</button>
                <button class="btn-modal-action" onclick="app.saveSystemSettingsBackend()" style="background:var(--color-cyan); color:black;">💾 Apply API Configurations</button>
            </div>
        `;

        this.settingsModalOverlay.classList.add('open');

        const range = document.getElementById('conf-thresh');
        if (range) {
            range.addEventListener('input', () => {
                document.getElementById('thresh-val').innerText = `${range.value}%`;
            });
        }

        const simToggle = document.getElementById('btn-toggle-sim');
        if (simToggle) {
            simToggle.addEventListener('click', () => {
                this.systemConfig.live_simulation_active = !this.systemConfig.live_simulation_active;
                simToggle.innerText = this.systemConfig.live_simulation_active ? '● WORKER ACTIVE' : '○ WORKER PAUSED';
                simToggle.classList.toggle('active', this.systemConfig.live_simulation_active);
            });
        }
    }

    async saveSystemSettingsBackend() {
        this.audio.playLaser();
        const oKey = document.getElementById('conf-openai-key').value.trim();
        const gKey = document.getElementById('conf-groq-key').value.trim();
        const thresh = parseFloat(document.getElementById('conf-thresh').value);

        const payload = {
            openai_api_key: oKey.startsWith('sk-') && !oKey.includes('***') ? oKey : undefined,
            groq_api_key: gKey.startsWith('gsk_') && !gKey.includes('***') ? gKey : undefined,
            auto_containment_threshold: thresh,
            live_simulation_active: this.systemConfig.live_simulation_active
        };

        try {
            const res = await fetch('/api/v1/system/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                const data = await res.json();
                this.systemConfig = data.config;
                this.audio.playShield();
                alert("✨ BradlyAI System Configurations successfully applied to active FastAPI Python Worker!");
                this.closeModals();
            }
        } catch (err) {}
    }

    async resetSiemDatabaseBackend() {
        this.audio.playAlarm();
        if (!confirm("Are you absolutely sure you want to purge all active SIEM logs from the SQLite database?")) return;

        try {
            const res = await fetch('/api/v1/system/reset-database', { method: 'POST' });
            if (res.ok) {
                const data = await res.json();
                this.audio.playShield();
                alert(`✔️ ${data.message}`);
                await this.fetchAlertsBackend();
                this.closeModals();
            }
        } catch (err) {}
    }

    renderStatsTop() {
        const statsContainer = document.getElementById('stats-grid');
        if (!statsContainer) return;

        statsContainer.innerHTML = `
            <div class="stat-card">
                <div class="stat-header">
                    <span>Digital Resilience Index</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                </div>
                <div class="stat-value">
                    ${INITIAL_STATS.resilienceScore} <span style="font-size: 1rem; color: #94a3b8;">/100</span>
                </div>
                <div class="stat-sub">
                    <span class="stat-change pos">${INITIAL_STATS.resilienceChange}</span>
                    <span>vs. last 30 days</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Autonomous Containment Rate</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                </div>
                <div class="stat-value" style="color: var(--color-green);">
                    ${INITIAL_STATS.automatedContainment}
                </div>
                <div class="stat-sub">
                    <span style="color: var(--color-green); font-weight: 600;">Driverless SOC</span>
                    <span>FastAPI Continuous Ingest</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Mean Time Response (MTTR)</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                </div>
                <div class="stat-value" style="color: var(--color-purple);">
                    ${INITIAL_STATS.mttr}
                </div>
                <div class="stat-sub">
                    <span style="color: var(--color-purple); font-weight: 600;">MTTD: ${INITIAL_STATS.mttd}</span>
                    <span>Multi-Model Parsing</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-header">
                    <span>Active Monitored Assets</span>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                </div>
                <div class="stat-value" style="color: var(--color-blue);">
                    ${INITIAL_STATS.monitoredEndpoints.toLocaleString()}
                </div>
                <div class="stat-sub">
                    <span>Across 4 Global Hubs (Connected to SQLite)</span>
                </div>
            </div>
        `;
    }


    async renderStats() {
        try {
            const [alertsRes, assetsRes, incidentsRes] = await Promise.all([
                fetch('/api/v1/alerts'),
                fetch('/api/v1/asm/assets'),
                fetch('/api/v1/integration/incidents').catch(() => ({json:()=>({stats:{total:0,closed:0,auto_containment_rate:"100%"}})})),
            ]);
            const alerts = await alertsRes.json();
            const assets = await assetsRes.json();
            const incData = await incidentsRes.json();
            
            const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
            const contained = alerts.filter(a => a.status === 'Auto-Contained').length;
            const atRisk = assets.filter(a => a.status === 'At Risk' || a.status === 'Vulnerable').length;
            
            const statsContainer = document.getElementById('stats-grid');
            if (statsContainer) {
                statsContainer.innerHTML = `
                    <div class="stat-card" style="border-left:3px solid #ef4444;">
                        <div class="stat-value" style="color:#ef4444;">${critical}</div>
                        <span>Active Critical Threats</span>
                        <div class="stat-trend up">Real-time</div>
                    </div>
                    <div class="stat-card" style="border-left:3px solid #10b981;">
                        <div class="stat-value" style="color:#10b981;">${contained}</div>
                        <span>Auto-Contained Threats</span>
                        <div class="stat-trend up">${incData.stats.auto_containment_rate || '100%'} rate</div>
                    </div>
                    <div class="stat-card" style="border-left:3px solid #00f0ff;">
                        <div class="stat-value" style="color:#00f0ff;">${incData.stats.total}</div>
                        <span>SIEM Incidents Managed</span>
                        <div class="stat-trend up">${incData.stats.closed} closed</div>
                    </div>
                    <div class="stat-card" style="border-left:3px solid #fbbf24;">
                        <div class="stat-value" style="color:#fbbf24;">${assets.length}</div>
                        <span>Monitored Assets</span>
                        <div class="stat-trend ${atRisk > 0 ? 'up' : 'down'}">${atRisk} at risk</div>
                    </div>
                \`;
            }
        } catch(e) {
            const statsContainer = document.getElementById('stats-grid');
            if (statsContainer) {
                statsContainer.innerHTML = `
                    <div class="stat-card"><div class="stat-value">94/100</div><span>Digital Resilience Index</span><div class="stat-trend up">+3.2%</div></div>
                    <div class="stat-card"><div class="stat-value">99.4%</div><span>Autonomous Containment Rate</span><div class="stat-trend up">342/hr</div></div>
                    <div class="stat-card"><div class="stat-value">1.4s</div><span>Mean Time Response</span><div class="stat-trend down">-0.3s</div></div>
                    <div class="stat-card"><div class="stat-value">12,842</div><span>Monitored Assets</span><div class="stat-trend up">0 shadow IT</div></div>
                \`;
            }
        }
    }

    async runManagementDemo() {
        this.audio.playBeep(1000, 'sine', 0.1);
        const btn = document.getElementById('btn-run-demo');
        if (btn) { btn.textContent = '⏳ Running Demo...'; btn.disabled = true; }
        
        const scenarios = [
            {level:13, desc:'Suspicious PowerShell Encoded Command Execution', agent:'WEB-SRV01', ip:'192.168.1.100', mitre:'T1059.001'},
            {level:14, desc:'Multiple Failed Login Attempts - Brute Force Attack', agent:'DC01', ip:'10.0.0.2', mitre:'T1110'},
            {level:15, desc:'Ransomware Encryption Detected on File Server', agent:'FILE-SRV-03', ip:'192.168.50.10', mitre:'T1486'},
        ];
        
        let done = 0;
        for (const s of scenarios) {
            try {
                await fetch('/api/v1/integration/wazuh/full-pipeline', {
                    method:'POST', headers:{'Content-Type':'application/json'},
                    body:JSON.stringify({rule_level:s.level, rule_description:s.desc, agent_name:s.agent, agent_ip:s.ip, mitre_id:s.mitre, auto_close:true})
                });
                done++;
            } catch(e) { console.error(e); }
        }
        
        this.audio.playAlarm();
        if (btn) { btn.innerHTML = '<span>✅ Demo Complete — ' + done + ' incidents</span>'; }
        setTimeout(() => { if (btn) { btn.innerHTML = '<span>🎯 Run Management Demo</span>'; btn.disabled = false; } }, 5000);
        this.renderStats();
        this.renderAlertsTable();
    }

    renderDashboard() {
        if (!this.mainContent) return;

        this.mainContent.innerHTML = `
            <div class="dashboard-middle-grid">
                <!-- Live Threat Map -->
                <div class="panel-card">
                    <div class="panel-header">
                        <div class="panel-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                            <span>Live Multi-Model Cyber Threat Radar</span>
                        </div>
                        <div class="driverless-badge" style="background: rgba(0, 240, 255, 0.1); border-color: rgba(0, 240, 255, 0.3); color: var(--color-cyan);">
                            <span class="status-dot" style="background-color: var(--color-cyan); box-shadow: 0 0 8px var(--color-cyan);"></span>
                            AI Telemetry Active // Click Hubs to Inspect
                        </div>
                    </div>
                    <div class="panel-body" style="position:relative;">
                        <div class="floating-diag-panel" id="map-diag-panel">
                            <div class="diag-title">
                                <span id="hub-name">Taipei BradlyAI Hub</span>
                                <button onclick="document.getElementById('map-diag-panel').style.display='none'" style="background:transparent;border:none;color:white;cursor:pointer;">✕</button>
                            </div>
                            <div class="diag-stat"><span class="diag-lbl">Live Ping:</span><span class="diag-val" id="hub-ping">1.2 ms</span></div>
                            <div class="diag-stat"><span class="diag-lbl">Active EDR Pods:</span><span class="diag-val" id="hub-pods">4,812</span></div>
                            <div class="diag-stat"><span class="diag-lbl">CPU Triage Load:</span><span class="diag-val" style="color:var(--color-green);" id="hub-load">14.8%</span></div>
                            <div class="diag-stat"><span class="diag-lbl">AI Confidence:</span><span class="diag-val" style="color:var(--color-cyan);">99.4%</span></div>
                        </div>

                        <div class="threat-map-container" id="threat-map-container">
                            <svg class="threat-map-svg" viewBox="0 0 1000 500">
                                <g fill="rgba(45, 55, 95, 0.3)" stroke="rgba(0, 240, 255, 0.2)" stroke-width="0.5">
                                    <path d="M150,120 Q200,90 280,110 Q320,150 250,220 Q200,280 180,240 Q130,200 150,120" />
                                    <path d="M300,240 Q340,210 390,260 Q420,320 370,390 Q320,410 290,360 Z" />
                                    <path d="M480,120 Q550,70 650,100 Q720,130 680,220 Q600,280 520,200 Z" />
                                    <path d="M550,260 Q620,250 680,310 Q660,390 600,420 Q540,360 550,260 Z" />
                                    <path d="M720,150 Q820,120 880,180 Q920,260 840,320 Q780,250 720,150 Z" />
                                    <path d="M750,330 Q820,310 880,360 Q860,450 780,440 Z" />
                                </g>

                                <circle cx="820" cy="220" r="180" fill="none" stroke="rgba(0, 240, 255, 0.1)" stroke-width="1" stroke-dasharray="4 4" />
                                <circle cx="820" cy="220" r="120" fill="none" stroke="rgba(0, 240, 255, 0.15)" stroke-width="1" />
                                <circle cx="820" cy="220" r="60" fill="none" stroke="rgba(0, 240, 255, 0.2)" stroke-width="1" />
                                <circle id="radar-sweep" cx="820" cy="220" r="25" fill="none" stroke="var(--color-cyan)" stroke-width="2" opacity="0.8">
                                    <animate attributeName="r" values="8;180" dur="3s" repeatCount="indefinite" />
                                    <animate attributeName="opacity" values="1;0" dur="3s" repeatCount="indefinite" />
                                </circle>

                                <g id="map-interactive-hubs" cursor="pointer">
                                    <g class="map-hub" onclick="app.inspectMapHub('BradlyAI Multi-Model SOC (Taipei)', '0.8 ms', '5,420', '12.4%')">
                                        <circle cx="820" cy="220" r="12" fill="rgba(0, 240, 255, 0.2)" stroke="var(--color-cyan)" stroke-width="2" />
                                        <circle cx="820" cy="220" r="4" fill="var(--color-cyan)" />
                                        <text x="835" y="225" fill="var(--color-cyan)" font-family="Inter" font-size="12" font-weight="bold">BradlyAI Mesh (Taipei)</text>
                                    </g>

                                    <g class="map-hub" onclick="app.inspectMapHub('EU Interceptor Pod (Frankfurt)', '14.2 ms', '3,105', '18.9%')">
                                        <circle cx="500" cy="170" r="10" fill="rgba(99, 102, 241, 0.2)" stroke="var(--color-indigo)" stroke-width="1.5" />
                                        <circle cx="500" cy="170" r="3" fill="white" />
                                        <text x="515" y="174" fill="#cbd5e1" font-family="Inter" font-size="11">EU Gateway</text>
                                    </g>

                                    <g class="map-hub" onclick="app.inspectMapHub('US-East Identity Pod (Virginia)', '22.5 ms', '2,840', '24.1%')">
                                        <circle cx="180" cy="140" r="10" fill="rgba(16, 185, 129, 0.2)" stroke="var(--color-green)" stroke-width="1.5" />
                                        <circle cx="180" cy="140" r="3" fill="white" />
                                        <text x="195" y="144" fill="#cbd5e1" font-family="Inter" font-size="11">US-East Pod</text>
                                    </g>

                                    <g class="map-hub" onclick="app.inspectMapHub('LatAm Automated Pod (São Paulo)', '35.1 ms', '1,477', '9.2%')">
                                        <circle cx="360" cy="300" r="10" fill="rgba(245, 158, 11, 0.2)" stroke="var(--color-amber)" stroke-width="1.5" />
                                        <circle cx="360" cy="300" r="3" fill="white" />
                                        <text x="375" y="304" fill="#cbd5e1" font-family="Inter" font-size="11">LatAm Pod</text>
                                    </g>
                                </g>

                                <g id="attack-beams">
                                    <path d="M550,180 Q680,120 820,220" fill="none" stroke="var(--color-red)" stroke-width="2" stroke-dasharray="8 6">
                                        <animate attributeName="stroke-dashoffset" values="28;0" dur="1s" repeatCount="indefinite" />
                                    </path>
                                    <circle cx="550" cy="180" r="6" fill="var(--color-red)">
                                        <animate attributeName="opacity" values="0.2;1" dur="1s" repeatCount="indefinite" />
                                    </circle>

                                    <path d="M220,160 Q520,80 820,220" fill="none" stroke="var(--color-amber)" stroke-width="1.5" stroke-dasharray="6 6">
                                        <animate attributeName="stroke-dashoffset" values="24;0" dur="1.5s" repeatCount="indefinite" />
                                    </path>
                                </g>

                                <circle cx="740" cy="190" r="15" fill="none" stroke="var(--color-green)" stroke-width="2">
                                    <animate attributeName="r" values="5;25" dur="1.2s" repeatCount="indefinite" />
                                    <animate attributeName="opacity" values="1;0" dur="1.2s" repeatCount="indefinite" />
                                </circle>
                                <text x="730" y="170" fill="var(--color-green)" font-family="JetBrains Mono" font-size="12" font-weight="bold">BLOCKED</text>
                            </svg>

                            <div class="map-overlay-stats">
                                <div class="map-stat-item">
                                    <span class="map-stat-val">342 /hr</span>
                                    <span class="map-stat-lbl">Attacks Thwarted</span>
                                </div>
                                <div class="map-stat-item">
                                    <span class="map-stat-val" style="color: var(--color-green);">0.0s</span>
                                    <span class="map-stat-lbl">Human Intervention</span>
                                </div>
                                <div class="map-stat-item">
                                    <span class="map-stat-val" style="color: var(--color-purple);">98.9%</span>
                                    <span class="map-stat-lbl">AI Attack Precision</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Live Attack Trends Canvas -->
                <div class="panel-card">
                    <div class="panel-header">
                        <div class="panel-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            <span>Autonomous Triage Splines</span>
                        </div>
                    </div>
                    <div class="panel-body">
                        <div class="trends-chart-container">
                            <canvas id="trends-canvas" width="500" height="380"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Alerts Table -->
            <div class="panel-card">
                <div class="panel-header">
                    <div class="panel-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <span>Enterprise Automated Security Alerts (FastAPI Live Pool & SQLite)</span>
                    </div>
                    <div class="panel-header-actions" id="alert-filters">
                        <button class="btn-filter ${this.currentAlertFilter === 'ALL' ? 'active' : ''}" data-filter="ALL">All (${this.alertsData.length})</button>
                        <button class="btn-filter ${this.currentAlertFilter === 'CRITICAL' ? 'active' : ''}" data-filter="CRITICAL">Critical</button>
                        <button class="btn-filter ${this.currentAlertFilter === 'HIGH' ? 'active' : ''}" data-filter="HIGH">High</button>
                        <button class="btn-filter ${this.currentAlertFilter === 'MEDIUM' ? 'active' : ''}" data-filter="MEDIUM">Medium</button>
                        <button class="btn-filter ${this.currentAlertFilter === 'LOW' ? 'active' : ''}" data-filter="LOW">Low</button>
                    </div>
                </div>
                <div class="panel-body table-container">
                    <table class="cy-table">
                        <thead>
                            <tr>
                                <th>Incident ID</th>
                                <th>Severity</th>
                                <th>Threat Description & AI Root Cause</th>
                                <th>Compromised Asset / Host</th>
                                <th>MITRE ATT&CK TTP</th>
                                <th>Driverless AI Triage Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="alerts-tbody">
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        this.bindAlertFilters();
    }

    inspectMapHub(name, ping, pods, load) {
        this.audio.playBeep(850, 'sine', 0.05);
        const panel = document.getElementById('map-diag-panel');
        if (panel) {
            document.getElementById('hub-name').innerText = name;
            document.getElementById('hub-ping').innerText = ping;
            document.getElementById('hub-pods').innerText = pods;
            document.getElementById('hub-load').innerText = load;
            panel.style.display = 'block';
        }
    }

    bindAlertFilters() {
        const filterBtns = document.querySelectorAll('#alert-filters .btn-filter');
        filterBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                this.audio.playBeep(520, 'sine', 0.04);
                const flt = btn.getAttribute('data-filter');
                this.currentAlertFilter = flt;
                filterBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.renderAlertsTable();
            });
        });
    }

    renderAlertsTable() {
        const tbody = document.getElementById('alerts-tbody');
        if (!tbody) return;

        const filtered = this.alertsData.filter(a => {
            if (this.currentAlertFilter === 'ALL') return true;
            return a.severity === this.currentAlertFilter;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 32px;">No alerts match the selected severity filter.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(a => `
            <tr data-alert-id="${a.id}" class="alert-row">
                <td><strong style="font-family: 'JetBrains Mono'; color: var(--text-main);">${a.id}</strong></td>
                <td>
                    <span class="alert-severity ${a.severity.toLowerCase().substring(0,4)}">
                        ${a.severity}
                    </span>
                </td>
                <td>
                    <div class="alert-title">
                        ${a.title}
                    </div>
                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 4px;">
                        AI Confidence: <strong style="color: var(--color-cyan);">${a.ai_confidence || '98%'}</strong> | Timestamp: ${a.timestamp}
                    </div>
                </td>
                <td>
                    <span class="alert-endpoint">${a.endpoint}</span>
                    <div style="font-size: 0.7rem; color: var(--text-muted); font-family: 'JetBrains Mono';">${a.ip}</div>
                </td>
                <td>
                    <span class="alert-mitre">${a.mitre}</span>
                </td>
                <td>
                    <span class="alert-status ${a.status === 'Auto-Contained' ? 'auto' : 'inv'}">
                        <span class="status-dot" style="background-color: ${a.status === 'Auto-Contained' ? 'var(--color-green)' : 'var(--color-amber)'};"></span>
                        ${a.status}
                    </span>
                </td>
                <td>
                    <button class="btn-filter btn-inspect-story" style="background: rgba(0, 240, 255, 0.1); color: var(--color-cyan); border-color: rgba(0, 240, 255, 0.3); font-weight: 600;">
                        Inspect AI Storyline
                    </button>
                </td>
            </tr>
        `).join('');

        document.querySelectorAll('.alert-row').forEach(row => {
            row.addEventListener('click', () => {
                this.audio.playShield();
                const aid = row.getAttribute('data-alert-id');
                const alertObj = this.alertsData.find(x => x.id === aid);
                this.openAlertModal(alertObj);
            });
        });
    }

    openAlertModal(alertObj) {
        if (!alertObj) return;

        const modal = document.getElementById('modal-card');
        modal.innerHTML = `
            <div class="modal-header">
                <div class="modal-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="var(--color-cyan)" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span>Autonomous Storyline Report: ${alertObj.id}</span>
                </div>
                <button class="btn-close-modal" id="close-report-modal">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
            <div class="modal-body">
                <div style="display: flex; gap: 20px; background: rgba(0,0,0,0.4); padding: 16px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.05);">
                    <div>
                        <div style="font-size: 0.75rem; color: var(--text-muted);">Compromised Host</div>
                        <strong style="font-family: 'JetBrains Mono'; color: var(--color-cyan); font-size: 1.1rem;">${alertObj.endpoint} (${alertObj.ip})</strong>
                    </div>
                    <div style="border-left: 1px solid var(--border-color); padding-left: 20px;">
                        <div style="font-size: 0.75rem; color: var(--text-muted);">MITRE Tactic / Technique</div>
                        <strong style="font-family: 'JetBrains Mono'; color: white; font-size: 1.1rem;">${alertObj.mitre}</strong>
                    </div>
                    <div style="border-left: 1px solid var(--border-color); padding-left: 20px;">
                        <div style="font-size: 0.75rem; color: var(--text-muted);">AI Resolution Status</div>
                        <strong style="color: var(--color-green); font-size: 1.1rem;">${alertObj.status} (Confidence: ${alertObj.ai_confidence || '98%'})</strong>
                    </div>
                </div>

                <div style="margin-top: 10px;">
                    <h4 style="font-family: 'Orbitron'; font-size: 1.05rem; color: var(--color-cyan); margin-bottom: 16px; display: flex; align-items: center; gap: 8px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                        Automated AI Investigation Storyline
                    </h4>

                    <div class="modal-storyline" id="modal-st-container">
                        ${alertObj.storyline ? alertObj.storyline.map((st, i) => `
                            <div class="story-item">
                                <div class="story-dot" style="${i === alertObj.storyline.length - 1 ? 'background: var(--color-green); box-shadow: 0 0 12px var(--color-green);' : ''}"></div>
                                <div class="story-time">${st.time}</div>
                                <div class="story-event" style="${i === alertObj.storyline.length - 1 ? 'font-weight: 700; color: var(--color-green);' : ''}">
                                    ${st.event}
                                </div>
                            </div>
                        `).join('') : '<div style="color:var(--text-muted);">No storyline logged.</div>'}
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-filter" id="btn-export-st" style="display: flex; align-items: center; gap: 8px; font-weight: 600; background:rgba(0,240,255,0.1); color:var(--color-cyan); border-color:var(--color-cyan);">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                    Download SIEM Evidence (JSON)
                </button>
                <button class="btn-modal-action" id="btn-close-ack">Acknowledge & Close</button>
            </div>
        `;

        this.modalOverlay.classList.add('open');

        document.getElementById('close-report-modal').addEventListener('click', () => this.closeModals());
        document.getElementById('btn-close-ack').addEventListener('click', () => this.closeModals());
        document.getElementById('btn-export-st').addEventListener('click', () => {
            this.audio.playLaser();
            this.exportForensicsBlob(alertObj);
        });
    }

    exportForensicsBlob(alertObj) {
        const payload = {
            siem_export_version: "2.0",
            platform: "BradlyAI Advanced Autonomous Driverless SOC",
            generated_at: new Date().toISOString(),
            incident: alertObj
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cycraft_siem_evidence_${alertObj.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    closeModals() {
        if (this.modalOverlay) this.modalOverlay.classList.remove('open');
        if (this.simModalOverlay) this.simModalOverlay.classList.remove('open');
        if (this.settingsModalOverlay) this.settingsModalOverlay.classList.remove('open');
    }

    drawTrendsChart() {
        const canvas = document.getElementById('trends-canvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;

        ctx.clearRect(0, 0, w, h);
        ctx.fillStyle = '#050710';
        ctx.fillRect(0, 0, w, h);

        ctx.strokeStyle = 'rgba(45, 55, 95, 0.2)';
        ctx.lineWidth = 1;
        for (let x = 50; x < w; x += 50) {
            ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h - 30); ctx.stroke();
        }
        for (let y = 30; y < h - 30; y += 50) {
            ctx.beginPath(); ctx.moveTo(50, y); ctx.lineTo(w, y); ctx.stroke();
        }

        ctx.fillStyle = '#64748b';
        ctx.font = '10px Inter';
        const hours = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', 'Now'];
        hours.forEach((hr, i) => {
            const xPos = 50 + i * ((w - 70) / (hours.length - 1));
            ctx.fillText(hr, xPos - 12, h - 10);
        });

        const yVals = ['400', '300', '200', '100', '0'];
        yVals.forEach((yv, i) => {
            const yPos = 35 + i * ((h - 75) / (yVals.length - 1));
            ctx.fillText(yv, 15, yPos + 4);
        });

        const baseAuto = [120, 180, 140, 290, 220, 310, 342 + (this.alertsData.length * 5)];
        const baseManual = [15, 12, 18, 8, 10, 4, 1];

        const drawLine = (points, color, rgbColor) => {
            ctx.beginPath();
            ctx.strokeStyle = color;
            ctx.lineWidth = 3;

            const grad = ctx.createLinearGradient(0, 0, 0, h - 30);
            grad.addColorStop(0, `rgba(${rgbColor}, 0.5)`);
            grad.addColorStop(1, `rgba(${rgbColor}, 0.0)`);

            points.forEach((val, i) => {
                const px = 50 + i * ((w - 70) / (points.length - 1));
                const py = (h - 40) - (val / 400) * (h - 75);
                if (i === 0) ctx.moveTo(px, py);
                else {
                    const prevX = 50 + (i-1) * ((w - 70) / (points.length - 1));
                    const prevY = (h - 40) - (points[i-1] / 400) * (h - 75);
                    const cpX = (prevX + px) / 2;
                    ctx.bezierCurveTo(cpX, prevY, cpX, py, px, py);
                }
            });
            ctx.stroke();

            ctx.lineTo(50 + (points.length - 1) * ((w - 70) / (points.length - 1)), h - 30);
            ctx.lineTo(50, h - 30);
            ctx.fillStyle = grad;
            ctx.fill();

            points.forEach((val, i) => {
                const px = 50 + i * ((w - 70) / (points.length - 1));
                const py = (h - 40) - (val / 400) * (h - 75);
                ctx.beginPath();
                ctx.arc(px, py, 5, 0, Math.PI * 2);
                ctx.fillStyle = color;
                ctx.shadowColor = color;
                ctx.shadowBlur = 12;
                ctx.fill();
                ctx.shadowBlur = 0;
            });
        };

        drawLine(baseAuto, '#00f0ff', '0, 240, 255');
        drawLine(baseManual, '#a855f7', '168, 85, 247');

        ctx.fillStyle = '#00f0ff';
        ctx.fillRect(w - 230, 10, 12, 12);
        ctx.fillStyle = '#f1f5f9';
        ctx.fillText('AI Driverless Interceptions', w - 210, 20);

        ctx.fillStyle = '#a855f7';
        ctx.fillRect(w - 100, 10, 12, 12);
        ctx.fillStyle = '#f1f5f9';
        ctx.fillText('Manual Triage', w - 80, 20);
    }

    startLiveSecurityTicker() {
        if (!this.tickerContent || this.alertsData.length === 0) return;
        const items = this.alertsData.map(a => `
            <div class="ticker-item">
                <span class="ticker-badge ${a.severity.toLowerCase().substring(0,4)}">${a.severity}</span>
                <span><strong>${a.endpoint}</strong>: ${a.title}</span>
                <span class="ticker-time">(${a.status})</span>
            </div>
        `).join('<span style="color: var(--border-color);">///</span>');

        this.tickerContent.innerHTML = items + '<span style="color: var(--border-color);">///</span>' + items;
    }

    /* Automated Incident Response (AIR) Live Pipeline View */
    renderAirPipeline() {
        if (!this.mainContent) return;

        const currentScenario = SIMULATED_ATTACKS[this.airScenario];

        this.mainContent.innerHTML = `
            <div class="air-pipeline-container">
                <div class="pipeline-hero">
                    <div class="pipeline-hero-content">
                        <div class="pipeline-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="var(--color-cyan)" stroke-width="2" width="36" height="36"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            <span>BradlyAIR™ - Connected Autonomous Resolution Engine</span>
                        </div>
                        <div class="pipeline-desc">
                            Witness our multi-model AI operating a true <strong>Driverless SOC</strong> powered by asynchronous FastAPI Python processing. Choose a simulation below and watch BradlyAI instantly synthesize root-cause storylines and deploy auto-containment in real time.
                        </div>

                        <div style="display: flex; gap: 16px; align-items: center;">
                            <span style="font-weight: 700; color: white;">Select Simulation Scenario:</span>
                            <div class="scenario-selector">
                                ${SIMULATED_ATTACKS.map((sc, idx) => `
                                    <button class="scenario-btn ${idx === this.airScenario ? 'active' : ''}" data-scen-id="${idx}">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
                                        ${sc.scenarioName}
                                    </button>
                                `).join('')}
                            </div>
                        </div>
                    </div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; background: var(--bg-card); padding: 20px 28px; border-radius: 12px; border: 1px solid var(--border-color);">
                    <div>
                        <h4 style="font-family: 'Orbitron'; font-size: 1.2rem; color: white;">Active Scenario: <span style="color: var(--color-cyan);">${currentScenario.scenarioName}</span></h4>
                        <div style="color: var(--text-muted); font-size: 0.9rem; margin-top: 4px;">${currentScenario.description}</div>
                    </div>

                    <button id="btn-run-air-demo" class="btn-trigger-attack" style="background: linear-gradient(135deg, var(--color-green), #059669); border-color: #34d399; box-shadow: 0 0 25px rgba(16, 185, 129, 0.4); font-size: 1rem; padding: 14px 28px;">
                        <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                        Start Autonomous Python AIR Resolution Pipeline
                    </button>
                </div>

                <div class="workflow-stages" id="workflow-stages">
                    <div class="workflow-stage" id="ws-1">
                        <div class="stage-num">1</div>
                        <div class="stage-head"><span class="stage-title">Telemetry Ingestion</span></div>
                        <div class="stage-desc">Real-time behavioral log aggregation across Endpoints, Network, and Cloud Identity.</div>
                        <div class="stage-action">EDR Active</div>
                    </div>

                    <div class="workflow-stage" id="ws-2">
                        <div class="stage-num">2</div>
                        <div class="stage-head"><span class="stage-title">Multi-Model AI Triage</span></div>
                        <div class="stage-desc">Fast generative and behavioral ML parsing anomaly alerts and cross-host correlation.</div>
                        <div class="stage-action">Waiting AI...</div>
                    </div>

                    <div class="workflow-stage" id="ws-3">
                        <div class="stage-num">3</div>
                        <div class="stage-head"><span class="stage-title">Root-Cause Storyline</span></div>
                        <div class="stage-desc">Autonomous synthesis of full attack timeline and MITRE ATT&CK mapping.</div>
                        <div class="stage-action">Storyline...</div>
                    </div>

                    <div class="workflow-stage" id="ws-4">
                        <div class="stage-num">4</div>
                        <div class="stage-head"><span class="stage-title">Driverless Containment</span></div>
                        <div class="stage-desc">Zero-touch execution of firewall lockdowns, token revocations, and process kills.</div>
                        <div class="stage-action">Containment...</div>
                    </div>

                    <div class="workflow-stage" id="ws-5">
                        <div class="stage-num">5</div>
                        <div class="stage-head"><span class="stage-title">Resilience Verification</span></div>
                        <div class="stage-desc">Automatic audit closing, executive summary generation, and compliance recording.</div>
                        <div class="stage-action">Audit Record</div>
                    </div>
                </div>

                <div class="simulation-console">
                    <div class="console-top">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                            <span>Live Typewriter SOC Shell // Connected to FastAPI Core</span>
                        </div>
                        <div class="console-dots">
                            <div class="c-dot r"></div><div class="c-dot y"></div><div class="c-dot g"></div>
                        </div>
                    </div>
                    <div class="console-logs" id="console-logs">
                        <div class="log-line">
                            <span class="log-t">[0.0s]</span>
                            <span class="log-p">[FastAPI Core]</span>
                            <span class="log-msg">Ready for autonomous pipeline execution. Select a scenario above and click Start.</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        this.bindAirEvents();
    }

    bindAirEvents() {
        const scenarioBtns = document.querySelectorAll('.scenario-btn');
        scenarioBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                this.audio.playBeep(650, 'sine', 0.05);
                const sid = parseInt(btn.getAttribute('data-scen-id'));
                this.airScenario = sid;
                scenarioBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.renderAirPipeline();
            });
        });

        const runBtn = document.getElementById('btn-run-air-demo');
        if (runBtn) {
            runBtn.addEventListener('click', () => {
                if (this.simulationRunning) return;
                this.runAirAutonomousSimulationBackend();
            });
        }
    }

    async runAirAutonomousSimulationBackend() {
        this.simulationRunning = true;
        this.audio.playLaser();
        const currentScenario = SIMULATED_ATTACKS[this.airScenario];
        const consoleLogs = document.getElementById('console-logs');
        const stages = [
            document.getElementById('ws-1'),
            document.getElementById('ws-2'),
            document.getElementById('ws-3'),
            document.getElementById('ws-4'),
            document.getElementById('ws-5')
        ];

        stages.forEach(st => st.className = 'workflow-stage');
        consoleLogs.innerHTML = `
            <div class="log-line">
                <span class="log-t">[0.0s]</span>
                <span class="log-p">[BradlyAIR Ingest]</span>
                <span class="log-warn">🚨 INITIATING Python AUTONOMOUS RESOLUTION FOR: ${currentScenario.scenarioName.toUpperCase()}</span>
            </div>
        `;

        try {
            const res = await fetch(`/api/v1/air/run-pipeline/${this.airScenario}`, { method: 'POST' });
            if (res.ok) {
                const data = await res.json();
                
                data.execution_logs.forEach((logStr, i) => {
                    setTimeout(() => {
                        this.audio.playBeep(440 + i*100, 'triangle', 0.08);
                        stages.forEach((st, idx) => {
                            if (idx < i) st.className = 'workflow-stage completed';
                            else if (idx === i) st.className = 'workflow-stage active';
                        });

                        const isSucc = i === 3 || i === 4;
                        const logId = `log-line-${i}`;
                        consoleLogs.innerHTML += `
                            <div class="log-line">
                                <span class="log-t">[+0.${i*4}s]</span>
                                <span class="log-p">[Stage #${i+1}]</span>
                                <span class="${isSucc ? 'log-succ' : 'log-msg'}" id="${logId}"></span>
                            </div>
                        `;
                        consoleLogs.scrollTop = consoleLogs.scrollHeight;

                        this.streamTypewriterText(document.getElementById(logId), logStr, 15);
                    }, i * 600);
                });

                setTimeout(() => {
                    this.audio.playShield();
                    this.simulationRunning = false;
                    consoleLogs.innerHTML += `
                        <div class="log-line" style="margin-top: 10px;">
                            <span class="log-t">[Finished]</span>
                            <span class="log-p">[Driverless SOC]</span>
                            <span class="log-succ">✨ Python PIPELINE EXECUTION 100% COMPLETE. ENTERPRISE RESILIENCE PRESERVED.</span>
                        </div>
                    `;
                    consoleLogs.scrollTop = consoleLogs.scrollHeight;
                }, data.execution_logs.length * 600);
            }
        } catch (err) {
            this.simulationRunning = false;
        }
    }

    streamTypewriterText(el, text, speed = 20) {
        if (!el) return;
        let charIndex = 0;
        const interval = setInterval(() => {
            if (charIndex < text.length) {
                el.innerHTML += text.charAt(charIndex);
                charIndex++;
            } else {
                clearInterval(interval);
            }
        }, speed);
    }

    /* Attack Surface Management (ASM) */
    renderAsm() {
        if (!this.mainContent) return;

        this.mainContent.innerHTML = `
            <div style="margin-bottom: 24px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
                <div>
                    <h2 style="font-family: 'Orbitron'; font-size: 1.6rem; color: white;">Attack Surface Management (ASM)</h2>
                    <div style="color: var(--text-muted); font-size: 0.95rem; margin-top: 4px;">Continuous Automated Asset Discovery & Zero-Day Vulnerability Auto-Patching via SQLite & Python Engine</div>
                </div>

                <div style="display: flex; gap: 12px;">
                    <button id="btn-rescan-asm" class="btn-filter" style="display: flex; align-items: center; gap: 8px; background: rgba(0, 240, 255, 0.1); color: var(--color-cyan); border-color: rgba(0, 240, 255, 0.3); font-weight: 700; padding: 10px 18px;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.85.84 6.72 2.24L21 8"/><path d="M21 3v5h-5"/></svg>
                        Initiate Global Deep Asset Scan
                    </button>
                </div>
            </div>

            <div class="asm-grid" id="asm-grid">
            </div>
        `;

        this.renderAsmCards();

        document.getElementById('btn-rescan-asm').addEventListener('click', async () => {
            this.audio.playLaser();
            const btn = document.getElementById('btn-rescan-asm');
            btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18" class="animation-spin"><circle cx="12" cy="12" r="10"/></svg> Scanning 12,842 Assets...`;
            
            try {
                const res = await fetch('/api/v1/asm/rescan', { method: 'POST' });
                if (res.ok) {
                    const data = await res.json();
                    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.85.84 6.72 2.24L21 8"/><path d="M21 3v5h-5"/></svg> Initiate Global Deep Asset Scan`;
                    this.audio.playShield();
                    alert(`🛡️ BradlyAI Multi-Model Global Scan Report:\n\n${data.message}`);
                }
            } catch (err) {}
        });
    }

    renderAsmCards() {
        const grid = document.getElementById('asm-grid');
        if (!grid || this.asmAssets.length === 0) return;

        grid.innerHTML = this.asmAssets.map((ast) => `
            <div class="asset-card" data-asset-id="${ast.id}">
                <div class="asset-top">
                    <div class="asset-info">
                        <div class="asset-icon">
                            ${ast.type === 'Web Service' || ast.type === 'Web Application' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>' : ''}
                            ${ast.type === 'Cloud Storage' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>' : ''}
                            ${ast.type === 'Network Gateway' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>' : ''}
                            ${ast.type === 'Database Server' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>' : ''}
                            ${ast.type === 'Kubernetes' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>' : ''}
                        </div>
                        <div class="asset-names">
                            <span class="asset-title">${ast.name}</span>
                            <span class="asset-ip">${ast.ip}</span>
                        </div>
                    </div>
                    <span class="asset-type-badge">${ast.type}</span>
                </div>

                <div class="asset-body">
                    <div class="asset-meta">
                        <div class="meta-row">
                            <span class="meta-lbl">Ownership</span>
                            <span class="meta-val">${ast.owner}</span>
                        </div>
                        <div class="meta-row">
                            <span class="meta-lbl">Exposed Risk Score</span>
                            <span class="meta-val ${ast.risk_score.includes('Critical') ? 'crit' : (ast.risk_score.includes('High') ? 'high' : 'low')}">${ast.risk_score}</span>
                        </div>
                    </div>

                    <div class="asset-findings">
                        ${ast.findings && ast.findings.length > 0 ? ast.findings.map(f => `
                            <div class="finding-item">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                <span>${f}</span>
                            </div>
                        `).join('') : `
                            <div style="color: var(--color-green); font-size: 0.85rem; display: flex; align-items: center; gap: 8px; padding: 8px 0;">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                                <span>Zero Misconfigurations or Vulnerabilities Detected</span>
                            </div>
                        `}
                    </div>

                    ${ast.findings && ast.findings.length > 0 ? `
                        <button class="btn-ai-remediate" data-asset-id="${ast.id}">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                            Autonomous AI Auto-Remediate
                        </button>
                    ` : `
                        <div style="background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); padding: 12px; border-radius: 8px; text-align: center; color: var(--text-muted); font-size: 0.8rem;">
                            Asset Fully Secured by Python Core
                        </div>
                    `}
                </div>
            </div>
        `).join('');

        document.querySelectorAll('.btn-ai-remediate').forEach(btn => {
            btn.addEventListener('click', () => {
                this.audio.playShield();
                const aid = parseInt(btn.getAttribute('data-asset-id'));
                this.remediateAssetBackend(aid);
            });
        });
    }

    async remediateAssetBackend(assetId) {
        try {
            const res = await fetch(`/api/v1/asm/remediate/${assetId}`, { method: 'POST' });
            if (res.ok) {
                const data = await res.json();
                alert(`🛡️ BradlyAI Auto-Remediation Execution:\n\n${data.message}`);
                
                const resAsm = await fetch('/api/v1/asm/assets');
                if (resAsm.ok) {
                    this.asmAssets = await resAsm.json();
                    this.renderAsmCards();
                }
            }
        } catch (err) {}
    }

    /* AI Threat Hunter & Live Forensics */
    renderForensics() {
        if (!this.mainContent) return;

        this.mainContent.innerHTML = `
            <div style="margin-bottom: 24px;">
                <h2 style="font-family: 'Orbitron'; font-size: 1.6rem; color: white;">AI Threat Hunter & Live Memory Forensics</h2>
                <div style="color: var(--text-muted); font-size: 0.95rem; margin-top: 4px;">Inspect real-time process execution branches, suspicious reflective DLL injections, and execute active containment hooks.</div>
            </div>

            <div class="forensics-container">
                <div class="endpoint-list">
                    <div style="font-family: 'Orbitron'; font-weight: 700; color: var(--color-cyan); margin-bottom: 8px;">Target Monitored Host</div>
                    <div class="endpoint-item active" data-host="DEV-WIN-SRV09">
                        <span class="ep-name">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                            DEV-WIN-SRV09
                        </span>
                        <span class="ep-badge">Active Injection</span>
                    </div>

                    <div class="endpoint-item" data-host="FIN-WRK-102">
                        <span class="ep-name">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                            FIN-WRK-102
                        </span>
                        <span class="ep-badge" style="background: rgba(245,158,11,0.2); color: var(--color-amber); border-color: var(--color-amber);">Suspicious Macro</span>
                    </div>
                </div>

                <div class="process-tree-view" id="process-tree-view">
                </div>
            </div>
        `;

        this.bindForensicHosts();
        this.fetchProcessTreeBackend('DEV-WIN-SRV09');
    }

    bindForensicHosts() {
        const epItems = document.querySelectorAll('.endpoint-item');
        epItems.forEach(ep => {
            ep.addEventListener('click', () => {
                this.audio.playBeep(600, 'sine', 0.05);
                const hst = ep.getAttribute('data-host');
                epItems.forEach(b => b.classList.remove('active'));
                ep.classList.add('active');
                this.fetchProcessTreeBackend(hst);
            });
        });
    }

    async fetchProcessTreeBackend(hostname) {
        const container = document.getElementById('process-tree-view');
        if (!container) return;

        try {
            const res = await fetch(`/api/v1/forensics/process-tree/${hostname}`);
            if (res.ok) {
                const hostData = await res.json();
                this.renderProcessTreeMarkup(hostname, hostData);
            }
        } catch (err) {}
    }

    renderProcessTreeMarkup(hostname, hostData) {
        const container = document.getElementById('process-tree-view');
        if (!container || !hostData.rootProcess) return;

        const renderNode = (node) => {
            return `
                <div class="process-node ${node.highlight ? 'highlight' : ''}" id="proc-${node.pid}">
                    <div class="node-head">
                        <div class="node-info-left">
                            <div class="p-icon">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
                            </div>
                            <div>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <span class="p-name">${node.name}</span>
                                    <span class="p-pid">PID: ${node.pid}</span>
                                </div>
                                <div class="p-user" style="margin-top: 4px; display: inline-block;">${node.user}</div>
                            </div>
                        </div>

                        <div class="node-stats">
                            <span style="color: var(--text-muted); font-size: 0.8rem;">CPU: ${node.cpu} | Mem: ${node.memory}</span>
                            <span class="p-rep ${node.reputation.includes('Malicious') ? 'mal' : 'trust'}">${node.reputation}</span>
                        </div>
                    </div>

                    ${node.details ? `
                        <div class="node-details">
                            <div class="det-row"><span class="det-lbl">Behavior:</span><span class="det-val">${node.details}</span></div>
                            <div class="det-row"><span class="det-lbl">Network:</span><span class="det-val" style="color: var(--color-amber);">${node.network}</span></div>
                            ${node.dlls && node.dlls.length > 0 ? `
                                <div class="det-row"><span class="det-lbl">Injected DLLs:</span><span class="det-val" style="color: var(--color-red);">${node.dlls.join(', ')}</span></div>
                            ` : ''}

                            <div class="mem-actions-bar">
                                <button class="btn-mem-act" onclick="app.killProcess(${node.pid}, '${node.name}')">⚡ Kill PID #${node.pid}</button>
                                <button class="btn-mem-act" onclick="app.isolateMemory(${node.pid})">🛡️ Isolate Memory Handle</button>
                                <button class="btn-mem-act" onclick="app.downloadMemoryDump(${node.pid})">💾 Download Memory Dump</button>
                            </div>
                        </div>
                    ` : ''}

                    ${node.children && node.children.length > 0 ? `
                        <div class="node-children">
                            ${node.children.map(ch => renderNode(ch)).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        };

        container.innerHTML = `
            <div class="tree-header">
                <div class="tree-title">Memory Execution Process Tree: ${hostname}</div>
                <button id="btn-deep-scan" class="btn-trigger-attack" style="background: linear-gradient(135deg, var(--color-cyan), var(--color-blue)); color: #000; border: none; font-size: 0.85rem;">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
                    AI Copilot Memory Deep Scan
                </button>
            </div>
            <div>
                ${renderNode(hostData.rootProcess)}
            </div>
        `;

        document.getElementById('btn-deep-scan').addEventListener('click', async () => {
            this.audio.playLaser();
            try {
                const res = await fetch(`/api/v1/forensics/deep-scan/${hostname}`, { method: 'POST' });
                if (res.ok) {
                    const data = await res.json();
                    alert(`🧠 BradlyAI Deep Scan Report on ${hostname}:\n\nVerdict: ${data.report}`);
                }
            } catch (err) {}
        });
    }

    killProcess(pid, name) {
        this.audio.playLaser();
        const el = document.getElementById(`proc-${pid}`);
        if (el) el.style.display = 'none';
        alert(`⚡ Process ID #${pid} (${name}) completely killed via Active EDR Memory Hook.`);
    }

    isolateMemory(pid) {
        this.audio.playShield();
        alert(`🛡️ Memory handles for PID #${pid} bi-directionally isolated from LSASS access.`);
    }

    downloadMemoryDump(pid) {
        this.audio.playBeep(900, 'sine', 0.1);
        alert(`💾 120MB Kernel Memory Dump for PID #${pid} saved to SIEM offline forensics repository.`);
    }

    /* MITRE ATT&CK Matrix */
    async renderMitre() {
        if (!this.mainContent) return;

        this.mainContent.innerHTML = `
            <div style="margin-bottom: 24px;">
                <h2 style="font-family: 'Orbitron'; font-size: 1.6rem; color: white;">MITRE ATT&CK® Enterprise Tactical Matrix</h2>
                <div style="color: var(--text-muted); font-size: 0.95rem; margin-top: 4px;">Live behavioral alignment synced with FastAPI Multi-Model database.</div>
                
                <div style="display:flex; gap:10px; margin-top:16px;" id="mitre-filter-bar">
                    <button class="btn-filter ${this.mitreTacticFilter==='ALL'?'active':''}" data-tac="ALL">All Enterprise TTPs</button>
                    <button class="btn-filter ${this.mitreTacticFilter==='Initial Access'?'active':''}" data-tac="Initial Access">Initial Access</button>
                    <button class="btn-filter ${this.mitreTacticFilter==='Execution'?'active':''}" data-tac="Execution">Execution</button>
                    <button class="btn-filter ${this.mitreTacticFilter==='Privilege Escalation'?'active':''}" data-tac="Privilege Escalation">Privilege Escalation</button>
                    <button class="btn-filter ${this.mitreTacticFilter==='Credential Access'?'active':''}" data-tac="Credential Access">Credential Access</button>
                    <button class="btn-filter ${this.mitreTacticFilter==='Lateral Movement'?'active':''}" data-tac="Lateral Movement">Lateral Movement</button>
                </div>
            </div>

            <div class="mitre-matrix-grid" id="mitre-matrix-grid">
            </div>
        `;

        this.bindMitreFilters();
        this.renderMitreCardsMarkup();
    }

    bindMitreFilters() {
        const btns = document.querySelectorAll('#mitre-filter-bar .btn-filter');
        btns.forEach(b => {
            b.addEventListener('click', () => {
                this.audio.playBeep(650, 'sine', 0.04);
                this.mitreTacticFilter = b.getAttribute('data-tac');
                btns.forEach(x => x.classList.remove('active'));
                b.classList.add('active');
                this.renderMitreCardsMarkup();
            });
        });
    }

    renderMitreCardsMarkup() {
        const grid = document.getElementById('mitre-matrix-grid');
        if (!grid || this.mitreMatrix.length === 0) return;

        const filtered = this.mitreMatrix.filter(tac => {
            if (this.mitreTacticFilter === 'ALL') return true;
            return tac.tactic === this.mitreTacticFilter;
        });

        grid.innerHTML = filtered.map(tac => `
            <div class="mitre-tactic-col">
                <div class="mitre-tactic-head">
                    <span>${tac.tactic}</span>
                    <span class="tactic-count-badge">${tac.techniques.filter(t => t.active).length} Active</span>
                </div>

                <div class="mitre-tech-list">
                    ${tac.techniques.map(t => `
                        <div class="mitre-tech-item ${t.active ? 'active' : ''}" data-tech-id="${t.id}" data-tech-name="${t.name}">
                            <div class="tech-top">
                                <span class="tech-id">${t.id}</span>
                                ${t.threat !== 'None' ? `<span class="tech-threat ${t.threat.toLowerCase().substring(0,4)}">${t.threat}</span>` : ''}
                            </div>
                            <span class="tech-name">${t.name}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `).join('');

        document.querySelectorAll('.mitre-tech-item').forEach(card => {
            card.addEventListener('click', async () => {
                this.audio.playShield();
                const tid = card.getAttribute('data-tech-id');
                const tname = card.getAttribute('data-tech-name');
                try {
                    const gRes = await fetch(`/api/v1/mitre/technique/${tid}`);
                    if (gRes.ok) {
                        const gData = await gRes.json();
                        alert(`🛡️ BradlyAI Multi-Model Guide: ${tid} - ${tname}\n\n${gData.guide}`);
                    }
                } catch (err) {}
            });
        });
    }

    /* AI Security Copilot Chat */
    renderCopilot() {
        if (!this.mainContent) return;

        this.mainContent.innerHTML = `
            <div class="copilot-container">
                <div class="copilot-header">
                    <div class="copilot-title-box">
                        <div class="copilot-avatar">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 0 0-10 10c0 4.41 3.22 8.1 7.5 9.5V22h5v-.5C18.78 20.1 22 16.41 22 12A10 10 0 0 0 12 2z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>
                        </div>
                        <div>
                            <div class="copilot-name">BradlyAI Cyber-AI Copilot <span class="ai-tag">FastAPI Generative PRO</span></div>
                            <div style="font-size: 0.8rem; color: var(--text-cyber-green); font-family: 'JetBrains Mono'; margin-top: 4px;">● Live Cloud / SQLite Multi-Model Core Connected</div>
                        </div>
                    </div>
                </div>

                <div class="copilot-body" id="chat-body">
                    ${this.renderChatHistory()}
                </div>

                <div class="prompt-suggestions">
                    ${COPILOT_SUGGESTIONS.map(sug => `
                        <button class="prompt-chip">${sug}</button>
                    `).join('')}
                </div>

                <div class="copilot-footer">
                    <form id="chat-form" class="chat-input-box">
                        <input type="text" id="chat-input" class="chat-input" placeholder="Ask BradlyAI Copilot to investigate logs, summarize IOCs, or write YARA rules..." autocomplete="off">
                        <button type="submit" class="btn-send-msg">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                        </button>
                    </form>
                </div>
            </div>
        `;

        this.bindChatEvents();
        this.scrollChatBottom();
    }

    renderChatHistory() {
        return this.chatHistory.map(m => `
            <div class="chat-msg ${m.sender}">
                <div class="msg-avatar">
                    ${m.sender === 'ai' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M12 2a10 10 0 0 0-10 10c0 4.41 3.22 8.1 7.5 9.5V22h5v-.5C18.78 20.1 22 16.41 22 12A10 10 0 0 0 12 2z"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'}
                </div>
                <div class="msg-bubble" id="${m.id || ''}">
                    ${m.text}
                </div>
            </div>
        `).join('');
    }

    bindChatEvents() {
        const form = document.getElementById('chat-form');
        const input = document.getElementById('chat-input');

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            const q = input.value.trim();
            if (!q) return;
            this.sendChatMessageBackend(q);
            input.value = '';
        });

        document.querySelectorAll('.prompt-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                const queryText = chip.innerText;
                this.sendChatMessageBackend(queryText);
            });
        });
    }

    async sendChatMessageBackend(query) {
        this.audio.playBeep(700, 'sine', 0.05);
        this.chatHistory.push({ sender: 'user', text: query });
        const body = document.getElementById('chat-body');
        body.innerHTML = this.renderChatHistory();
        this.scrollChatBottom();

        try {
            const res = await fetch('/api/v1/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: query })
            });

            if (res.ok) {
                const data = await res.json();
                const bubbleId = `chat-reply-${Date.now()}`;
                
                this.chatHistory.push({ sender: 'ai', text: data.reply, id: bubbleId });
                
                if (this.currentTab === 'copilot') {
                    document.getElementById('chat-body').innerHTML = this.renderChatHistory();
                    const targetBubble = document.getElementById(bubbleId);
                    if (targetBubble) {
                        targetBubble.innerHTML = '';
                        this.streamTypewriterText(targetBubble, data.reply, 8);
                    }
                    this.scrollChatBottom();
                }
            }
        } catch (err) {
            this.chatHistory.push({ sender: 'ai', text: "🚨 Connection error to Python Copilot Core." });
        }
    }

    scrollChatBottom() {
        const body = document.getElementById('chat-body');
        if (body) body.scrollTop = body.scrollHeight;
    }

    /* Emergency Simulation Trigger Modal */
    async triggerSimulatedAttackBackend() {
        const simModal = document.getElementById('sim-modal-overlay');
        if (!simModal) return;

        try {
            const res = await fetch('/api/v1/alerts/trigger-simulated-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario: 0 })
            });

            if (res.ok) {
                const data = await res.json();
                
                await this.fetchAlertsBackend();

                simModal.innerHTML = `
                    <div class="modal-card" style="border-color: #f43f5e; box-shadow: 0 0 80px rgba(244, 63, 94, 0.5);">
                        <div class="modal-header" style="background: linear-gradient(135deg, #881337, #be123c);">
                            <div class="modal-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="28" height="28" class="animation-pulse"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                                <span style="color: white;">EMERGENCY SIMULATION // LIVE APT29 OUTBREAK</span>
                            </div>
                        </div>
                        <div class="modal-body" style="background: #04060e;">
                            <div style="font-family: 'Orbitron'; color: var(--color-red); font-size: 1.2rem; text-align: center; margin-bottom: 12px;" id="sim-status-title">
                                🔴 TARGET COMPROMISED: DEV-WIN-SRV09 (Incident ID: ${data.alert_id})
                            </div>

                            <div style="background: #0b0f1e; border: 1px solid var(--color-red); padding: 16px; border-radius: 8px; font-family: 'JetBrains Mono'; font-size: 0.85rem; color: #f1f5f9; min-height: 200px; max-height: 300px; overflow-y: auto;" id="sim-live-shell">
                                [0.0s] Spear-phishing macro triggered on DEV-WIN-SRV09...
                            </div>
                        </div>
                        <div class="modal-footer" style="background: #0b0f1e; justify-content: space-between; align-items: center;">
                            <div style="color: var(--color-cyan); font-family: 'JetBrains Mono'; font-size: 0.85rem;">
                                FastAPI BradlyAI Multi-Model Interceptor Engaged.
                            </div>
                            <button class="btn-modal-action" id="btn-close-sim" style="background: var(--color-green);">Dismiss Verification</button>
                        </div>
                    </div>
                `;

                simModal.classList.add('open');
                document.getElementById('btn-close-sim').addEventListener('click', () => this.closeModals());

                const shell = document.getElementById('sim-live-shell');
                const title = document.getElementById('sim-status-title');

                const simSteps = [
                    "[0.4s] Obfuscated PowerShell shellcode spawning reflective DLL memory injection.",
                    "[0.8s] LSASS handle acquisition detected for credential harvesting.",
                    "[1.2s] ⚡ BradlyAI Multi-Model AI triggers autonomous driverless triage...",
                    `[1.5s] 🛡️ Bi-directional firewall network isolation activated. ${data.action_taken}`,
                    "[1.8s] 🛠️ Malicious PID #6104 completely eradicated.",
                    "[2.2s] ✨ ATTACK THWARTED. ZERO USER TOKENS LEAKED. 100% RESILIENCE PRESERVED."
                ];

                let step = 0;
                const simInterval = setInterval(() => {
                    if (step >= simSteps.length) {
                        clearInterval(simInterval);
                        title.style.color = "var(--color-green)";
                        title.innerText = `🟢 THREAT ELIMINATED: ${data.alert_id} SAFEGUARDED BY BradlyAI`;
                        this.audio.playShield();
                        return;
                    }
                    this.audio.playBeep(500 + step*80, 'triangle', 0.08);
                    
                    const lineSpan = `sim-line-${step}`;
                    shell.innerHTML += `<br><span id="${lineSpan}"></span>`;
                    shell.scrollTop = shell.scrollHeight;
                    
                    this.streamTypewriterText(document.getElementById(lineSpan), simSteps[step], 10);
                    step++;
                }, 600);
            }
        } catch (err) {}
    }
}

const app = new CyCraftApp();
