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

## License

This repository contains only the AI enhancement layer.

Wazuh components (Manager, Indexer, Agents) must be installed separately and remain governed by their original license.

All original code in this repository is released under the MIT License.

---

## Disclaimer

Research / academic prototype.
Not production hardened.
