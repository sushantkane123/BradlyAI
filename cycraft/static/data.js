/**
 * Default Initial Stats and Data Constants for CyCraft AI Frontend
 * Real datasets will be dynamically synchronized via FastAPI REST APIs & Live WebSockets!
 */

const INITIAL_STATS = {
    resilienceScore: 94,
    resilienceChange: "+3.2%",
    mttd: "1.2s",
    mttr: "4.5s",
    automatedContainment: "99.4%",
    activeAlerts: 7,
    monitoredEndpoints: 12842,
    threatLevel: "ACTIVE"
};

const SIMULATED_ATTACKS = [
    {
        scenarioName: "APT29 Stealth Lateral Movement & Ransomware",
        description: "Simulates an advanced persistent threat compromising an internal developer machine, attempting privilege escalation via LSASS memory dumping, and spreading ransomware across the internal subnet.",
        steps: [
            { step: 1, title: "Initial Access Intercepted", desc: "Spear-phishing attachment executed on DEV-WRK-404. Malicious macro spawns obfuscated script.", time: "0.1s", action: "Detected T1566" },
            { step: 2, title: "Behavioral AI Triage", desc: "CyCraft Multi-Model AI instantly correlates process injection with unusual network callback to 185.190.24.1.", time: "0.4s", action: "Correlating TTPs" },
            { step: 3, title: "Automated Root-Cause Storyline", desc: "Attack graph fully synthesized. Found matching APT29 signature and active Kerberoasting attempts.", time: "0.8s", action: "Mapping MITRE" },
            { step: 4, title: "Driverless Containment Triggered", desc: "Executing auto-mitigation: Bi-directional network isolation of DEV-WRK-404, killing process ID #4912, revoking compromised JWT tokens.", time: "1.2s", action: "Host Isolated" },
            { step: 5, title: "Full Resolution & Report", desc: "Incident auto-closed. Zero data exfiltrated. Executive compliance & forensics report generated.", time: "1.6s", action: "Resilience Maintained" }
        ]
    },
    {
        scenarioName: "Zero-Day Supply Chain Exploitation",
        description: "Simulates a compromised third-party software dependency in your CI/CD build pipeline attempting to establish an unauthorized C2 reverse shell to an external server.",
        steps: [
            { step: 1, title: "Anomalous Pipeline Outbound Call", desc: "Jenkins build node initiates unexpected TLS connection to unregistered external IP.", time: "0.1s", action: "Detected T1195" },
            { step: 2, title: "AI Code Behavior Inspection", desc: "CyCraft AI Memory Scanner identifies dynamic payload execution in memory without file backup.", time: "0.4s", action: "Memory Scanned" },
            { step: 3, title: "Attack Surface Cross-Check", desc: "Determined compromised asset is AWS Container Instance #884. No lateral spread yet.", time: "0.8s", action: "Asset Tagged" },
            { step: 4, title: "Autonomous Containment", desc: "Container automatically paused via AWS ECS API, malicious egress IP blocked at Cloudflare WAF.", time: "1.2s", action: "WAF Rule Added" },
            { step: 5, title: "Vulnerability Patch Issued", desc: "Automated Pull Request generated to revert vulnerable NPM package in repository.", time: "1.6s", action: "PR Created" }
        ]
    }
];

const COPILOT_SUGGESTIONS = [
    "Summarize today's top critical security threats",
    "How did CyCraft AI autonomously block the Jenkins breach on DEV-WIN-SRV09?",
    "Generate a digital resilience summary for our Board of Directors",
    "Explain our MITRE ATT&CK coverage and defensive gaps",
    "Write an auto-remediation YARA rule for reflective DLL injection"
];
