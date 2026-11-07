# VegaIntel | Threat Intelligence Platform

VegaIntel is an automated, centralized Threat Intelligence Platform (TIP) engineered to continuously collect Indicators of Compromise (IOCs) across 5 open-source threat feeds (AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar, and Feodo Tracker), enrich and correlate them with NVD CVEs, MITRE ATT&CK threat actors, and weaponized exploit PoCs, and persist them into a deduplicated intelligence repository.

---

## 1. System Architecture Overview

```
Cron / Interval Scheduler
       │
       ▼
Python Collection Engine
       │
       ├──► NVD API ──► CVE Discovery & CVSS Scoring
       │
       ├──► CVE Enrichment Orchestrator
       │       │
       │       ├──► 5 OSINT Feeds:
       │       │     ├── AlienVault OTX
       │       │     ├── ThreatFox (abuse.ch)
       │       │     ├── URLhaus (abuse.ch)
       │       │     ├── MalwareBazaar (abuse.ch)
       │       │     └── Feodo Tracker (abuse.ch)
       │       │
       │       ├──► PoC Collector (GitHub / Exploit-DB / Metasploit)
       │       └──► MITRE ATT&CK Collector (Threat Actors & Techniques)
       │
       ▼
IOC Parser & Normalizer (Defanging, Casing, Syntax Validation)
       │
       ▼
Evidence Validation (RFC1918 filter, Benign domain pruning)
       │
       ▼
Fingerprint Generation: normalized_ioc_type + ":" + normalized_ioc_value
       │
       ├──► IOC Exists?
       │     ├── [YES] ──► Update Sighting Count, Sources, Dynamic Confidence
       │     └── [NO]  ──► Insert Canonical Record
       │
       ▼
Immutable Sightings Recording & Decoupled Relationship Mapping
       │
       ▼
MongoDB + Redis Cache
       │
       ▼
FastAPI REST & STIX 2.1 Backend ◄──► React + Ark UI Dark SaaS Dashboard
```

---

## 2. Core Deduplication Logic

When disparate feeds report the exact same indicator, VegaIntel creates **one canonical record** rather than duplicate entries.

### Fingerprint Computation
$$\text{Fingerprint} = \text{normalized\_ioc\_type} + \text{":"} + \text{normalized\_ioc\_value}$$

- `hxxps[:]//evil-domain[.]com[/]payload` $\rightarrow$ `url:https://evil-domain.com/payload`
- `OAST[.]LIVE` $\rightarrow$ `domain:oast.live`
- `194[.]38[.]20[.]41` $\rightarrow$ `ip:194.38.20.41`
- `E3B0C44298FC...` $\rightarrow$ `sha256:e3b0c44298fc...`

### Deduplication Ratio Metric
$$\text{Deduplication Savings Ratio} = 1 - \frac{\text{Unique Canonical IOCs}}{\text{Total Raw Sightings}}$$

---

## 3. MongoDB Collections Structure

| Collection | Schema / Purpose |
| :--- | :--- |
| `iocs` | Canonical deduplicated records (`fingerprint` unique index, `sighting_count`, `sources`, `overall_confidence`) |
| `sightings` | Immutable observation log (`ioc_fingerprint`, `source`, `observed_at`, `raw_payload`, `feed_confidence`) |
| `relationships` | Decoupled many-to-many threat graph (`source_id`, `target_id`, `relation_type`, `confidence`) |
| `cves` | Vulnerability catalog (`cve_id` index, `cvss_score`, `severity`, `description`, `cwe_ids`) |
| `apt_groups` | MITRE threat actors (`group_id`, `aliases`, `origin_country`, `techniques`, `associated_malware`) |
| `malware` | Malware families & payloads (`malware_id`, `type`, `sample_hashes`, `known_c2_servers`) |
| `poc_references` | Verified exploit references (`cve_id`, `source`, `url`, `advisory`, `reliability`) |
| `feed_status` | Operational telemetry per source (`status`, `last_successful_sync`, `total_ingested`) |
| `ingestion_jobs` | Granular audit trail of each sync job (`records_processed`, `duplicates_prevented`) |

---

## 4. Dashboard Modules (Executive Light Theme with Orange Accents)

1. **Platform Overview**: Live telemetry, deduplication efficiency percentage, active feed status pills, IOC distribution, and real-time sightings stream.
2. **CVE Explorer**: Vulnerability discovery, CVSS gauge, correlated canonical IOC count, PoC exploit indicators, and detailed drill-down modal.
3. **IOC Repository**: Filter by type (`IP`, `Domain`, `URL`, `SHA-256`, `MD5`) and feed. Modal reveals independent sighting timestamps, raw feed JSON, and multi-source corroboration.
4. **Threat Correlation Graph**: Interactive topological network showing relationships between CVEs, IOCs, Malware, and APT Actors.
5. **APT Groups**: Threat actor profiles (Lazarus Group, APT29 Cozy Bear, Volt Typhoon, LockBit Affiliates), target sectors, and MITRE techniques.
6. **Malware & Payloads**: Ransomware strains, C2 beacons, sample hashes, and C2 endpoints.
7. **PoC Library**: GitHub, Exploit-DB, and Metasploit references with mandatory safety advisory notices (metadata only, zero headless execution).
8. **Feed Monitoring**: Real-time status of 5 OSINT feeds + NVD & MITRE, ingestion job history, and manual synchronization trigger.
9. **Export & SIEM Integration**: One-click download of OASIS STIX 2.1 JSON bundle, CSV export, raw JSON dump, and copyable cURL snippets.

---

## 5. Configuration & API Keys (`.env`)

VegaIntel loads configuration and threat feed API keys from `.env` in the project root (`c:\Users\Sivasankar\Documents\VegaIntel\.env`) or from `backend/.env`.

A template `.env.example` is provided:
```bash
# Copy the template to activate your environment
cp .env.example .env
```

### Supported Environment Variables:

| Variable | Description | Source / How to Obtain | Required? |
| :--- | :--- | :--- | :--- |
| `OTX_API_KEY` | AlienVault OTX API key for threat pulses and IOCs | Free at [AlienVault OTX API](https://otx.alienvault.com/api) | Recommended |
| `NVD_API_KEY` | NIST NVD 2.0 API key (boosts rate limits 10x) | Free at [NIST NVD Key Request](https://nvd.nist.gov/developers/request-an-api-key) | Recommended |
| `ABUSE_CH_AUTH_KEY` | abuse.ch Auth-Key for ThreatFox, URLhaus & MalwareBazaar | Free at [abuse.ch Auth](https://auth.abuse.ch/) | Recommended |
| `GITHUB_TOKEN` | GitHub Personal Access Token for live PoC exploit search | Free at [GitHub Token Settings](https://github.com/settings/tokens) | Optional (Recommended) |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 API key for enrichment | Free at [VirusTotal](https://www.virustotal.com/gui/my-apikey) | Optional |
| `MONGO_URI` | MongoDB connection URI (`mongodb://localhost:27017`) | In-memory fallback if absent | Optional |
| `REDIS_URL` | Redis cache connection URI (`redis://localhost:6379/0`) | In-memory fallback if absent | Optional |
| `JWT_SECRET` | Secret key used for signing analyst JWT session tokens | Auto-configured default | Production |

> [!NOTE]
> Even without any API keys configured, VegaIntel immediately collects from keyless live feeds (CISA KEV, abuse.ch Feodo Tracker, Emerging Threats IP blocklist, OpenPhish feed, and public NIST NVD & GitHub endpoints). Adding your free keys unlocks full rate limits and AlienVault OTX threat pulses.

---

## 6. Quick Start & Execution

### Option A: Local Development (FastAPI + Embedded UI)
```powershell
# 1. Launch Unified Server
powershell -ExecutionPolicy Bypass -File start.ps1
```
Or manually:
```bash
$env:PYTHONPATH="backend"
python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000
```
- Web Dashboard: `http://localhost:8000`
- Interactive API Docs: `http://localhost:8000/docs`
- STIX 2.1 Export: `http://localhost:8000/api/export/stix`

### Option B: Docker Containerized Deployment
```bash
docker-compose up -d --build
```
- Frontend UI: `http://localhost:3000`
- Backend API: `http://localhost:8000`

### Running the Test Suite
```bash
$env:PYTHONPATH="backend"
python -m pytest backend/tests/ -v
```
Verifies the exact Section 3 scenario:
$$\text{2 Unique IOCs} \quad\longleftrightarrow\quad \text{4 Sightings} \quad\longleftrightarrow\quad \text{2 Duplicates Prevented}$$

