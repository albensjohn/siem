// --- CONFIGURATION ---
const MANAGER_URL = "/wazuh-api";
const INDEXER_URL = "/indexer-api";
const AI_DATA_URL = "data/ai_risks.json";
const PASS = "SecretPassword"; // Matches your docker-compose env

let mgrToken = "";

// --- INITIALIZATION ---
document.addEventListener("DOMContentLoaded", async () => {
    // 1. Authenticate
    await authManager();
    
    // 2. Initial Fetch
    refreshAll();

    // 3. Set Polling Loop (Every 5 seconds)
    setInterval(refreshAll, 5000);
});

async function refreshAll() {
    if (mgrToken) fetchAgents();
    fetchRealAlerts();
    fetchAiRisks();
}

// --- AUTHENTICATION (Manager) ---
async function authManager() {
    try {
        const creds = btoa(`wazuh-wui:${PASS}`);
        const res = await fetch(`${MANAGER_URL}/security/user/authenticate`, {
            method: "POST",
            headers: { "Authorization": `Basic ${creds}` }
        });
        
        if (res.ok) {
            const data = await res.json();
            mgrToken = data.data.token;
            document.getElementById("mgr-status").classList.add("online");
            document.getElementById("mgr-status").classList.remove("offline");
        } else {
            console.error("Manager Auth Failed");
        }
    } catch (e) { console.error("Manager Connection Error", e); }
}

// --- GET AGENTS (From Manager) ---
async function fetchAgents() {
    try {
        const res = await fetch(`${MANAGER_URL}/agents?pretty=true`, {
            headers: { "Authorization": `Bearer ${mgrToken}` }
        });
        const data = await res.json();
        const agents = data.data.affected_items;
        
        document.getElementById("kpi-agents").innerText = agents.length;
        
        const list = document.getElementById("agent-list");
        list.innerHTML = ""; // Clear list

        agents.forEach(a => {
            const statusClass = a.status === "active" ? "active" : "disconnected";
            const html = `
                <div class="list-item">
                    <span>${a.name} <span style="font-size:10px; color:#64748b">(${a.ip})</span></span>
                    <span class="badge ${statusClass}">${a.status}</span>
                </div>`;
            list.innerHTML += html;
        });

    } catch (e) { console.log("Agent Fetch Error"); }
}

// --- GET REAL LOGS (From Indexer Port 9200) ---
async function fetchRealAlerts() {
    try {
        // Query: Sort by timestamp desc, size 10, Level >= 3
        const query = {
            "size": 10,
            "sort": [{ "@timestamp": "desc" }],
            "query": { "range": { "rule.level": { "gte": 3 } } }
        };

        const creds = btoa(`admin:${PASS}`);
        const res = await fetch(`${INDEXER_URL}/wazuh-alerts-*/_search`, {
            method: "POST",
            headers: {
                "Authorization": `Basic ${creds}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify(query)
        });

        if(res.ok) {
            document.getElementById("idx-status").classList.add("online");
            document.getElementById("idx-status").classList.remove("offline");
        }

        const data = await res.json();
        const hits = data.hits.hits;
        
        // Update KPI
        document.getElementById("kpi-alerts").innerText = data.hits.total.value;

        // Populate Table
        const tbody = document.getElementById("alert-table-body");
        tbody.innerHTML = "";

        hits.forEach(hit => {
            const src = hit._source;
            const time = new Date(src["@timestamp"]).toLocaleTimeString();
            const level = src.rule.level;
            const desc = src.rule.description;
            const agent = src.agent.name || "Manager";
            
            // Color Coding
            let color = "#10b981"; // Green
            if (level >= 10) color = "#ef4444"; // Red
            else if (level >= 5) color = "#f59e0b"; // Orange

            const row = `
                <tr>
                    <td><span style="color:${color}; font-weight:bold">L${level}</span></td>
                    <td>${time}</td>
                    <td>${agent}</td>
                    <td style="color:#cbd5e1">${desc}</td>
                </tr>
            `;
            tbody.innerHTML += row;
        });

    } catch (e) {
        document.getElementById("alert-table-body").innerHTML = `<tr><td colspan="4" class="text-center">Connection Lost to Database</td></tr>`;
    }
}

// --- GET AI RISKS (From JSON File) ---
async function fetchAiRisks() {
    try {
        const res = await fetch(AI_DATA_URL);
        const data = await res.json();
        
        const feed = document.getElementById("ai-feed");
        feed.innerHTML = "";
        
        let highRiskCount = 0;

        for (const [agent, risk] of Object.entries(data)) {
            if (agent === "System") continue;
            
            if (risk.status === "CRITICAL" || risk.status === "HIGH") highRiskCount++;

            const html = `
                <div class="risk-card ${risk.status}">
                    <div style="display:flex; justify-content:space-between; font-size:12px; font-weight:bold; margin-bottom:4px">
                        <span>${agent}</span>
                        <span>Score: ${risk.risk_score}</span>
                    </div>
                    <div style="font-size:11px; color:#94a3b8">Anomalies: ${risk.anomalies}</div>
                </div>
            `;
            feed.innerHTML += html;
        }
        
        document.getElementById("kpi-risks").innerText = highRiskCount;

    } catch (e) {}
}