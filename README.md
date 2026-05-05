# SENTINEL SIEM

**AI-Enhanced Intelligence Layer for Wazuh**

## Overview

SENTINEL SIEM extends the Wazuh stack with AI-driven intelligence.

It adds:

* Behavioral anomaly detection (Isolation Forest)
* Risk aggregation & alert noise reduction
* MITRE ATT&CK correlation
* LLM-based threat explanation
* Natural language security queries

This project enhances Wazuh — it does not replace or redistribute it.

---

## Architecture

Wazuh Agents
→ Wazuh Manager
→ Wazuh Indexer
→ Feature Extraction
→ Isolation Forest
→ Risk Aggregation
→ MITRE Mapping
→ LLM Reasoning
→ Dashboard

---

## Requirements

* Docker + Docker Compose
* Wazuh Docker deployment
* OpenRouter API key (for LLM)

---

## Setup

### 1️⃣ Configure LLM API Key

```bash
mv .env.example .env
nano .env
```

Add your OpenRouter API key inside `.env`.

---

### 2️⃣ Generate Wazuh Certificates (Docker Deployment)

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

---

### 3️⃣ Start the Stack

```bash
docker compose up -d --build
```

If running on Linux with helper script:

```bash
./start.sh
```

---

### 4️⃣ Configuring Arch Linux Agents (systemd-journald)

If your Wazuh agent is running on Arch Linux (or any OS where logs are exclusively in the `systemd` journal rather than `/var/log/auth.log`), the agent will be blind to SSH and authentication failures by default. 

To fix this, edit `/var/ossec/etc/ossec.conf` on the agent machine and add the following block inside `<ossec_config>`:

```xml
  <localfile>
    <log_format>journald</log_format>
  </localfile>
```
Then restart the agent: `sudo systemctl restart wazuh-agent`.

---

## AI Engine Scoring (Isolation Forest)

The AI Engine calculates a **Global Risk Score** from 0% to 100%:
* **0% - 39% (LOW)**: Normal behavior. No anomalies detected.
* **40% - 59% (MEDIUM)**: Slight deviations from the baseline (e.g., unexpected rule triggers).
* **60% - 79% (HIGH)**: Highly suspicious activity deviating significantly from normal.
* **80% - 100% (CRITICAL)**: Massive, unprecedented deviations (e.g., active brute-force or privilege escalation).

**Note on Baseline Recalibration:** The AI Engine uses unsupervised learning and keeps a rolling history of the last 500 feature cycles. It retrains itself every 10 cycles. If an attack is sustained over a long period of time, the model will eventually learn that the attack is the "new normal" and the risk score will drop back down to LOW. To test and see high risk spikes, the system must establish a clean baseline of normal activity first.

---

## License

This repository contains only the AI enhancement layer.

Wazuh components (Manager, Indexer, Agents) must be installed separately and remain governed by their original license.

All original code in this repository is released under the MIT License.

---

## Disclaimer

Research / academic prototype.
Not production hardened.
