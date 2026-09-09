# SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-brightgreen.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Cryptography](https://img.shields.io/badge/Security-NIST_SP_800--52r2-red.svg)](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
[![Authorship](https://img.shields.io/badge/Architect-Ibrahim_Ali-orange.svg)](#authorship--integrity-watermark)

**SecureMailScope** is an enterprise-grade, passive network forensic framework designed to ingest PCAP/PCAPNG packet captures, reconstruct mail protocol communications (SMTP, IMAP, POP3), and evaluate cryptographic state transitions (TLS/STARTTLS). Utilizing unsupervised machine learning (Isolation Forests) coupled with Explainable AI (XAI) feature attribution, SecureMailScope detects cryptographic downgrade attacks (e.g., STRIPTLS), flags weak ciphers and expired certificates, and evaluates compliance with **NIST SP 800-52 Rev. 2**, **PCI-DSS v4.0**, and **CIS Benchmarks**.

---

## 🏛️ System Architecture

```
                       PASSIVE NETWORK FORENSIC ARCHITECTURE

 +--------------------------------------------------------------------------------+
 |                           PCAP / PCAPNG INGESTION                              |
 |   - O(1) Memory Constant Streaming Parser (Multi-Gigabyte captures supported)  |
 |   - Ethernet II, 802.1Q / QinQ VLAN Tagging, IPv4 & IPv6 Decoders              |
 +---------------------------------------+----------------------------------------+
                                         |
                                         v
 +--------------------------------------------------------------------------------+
 |                     TCP REASSEMBLY & PROTOCOL CLASSIFICATION                   |
 |   - 5-Tuple Connection Tracking (Client <-> Server Flow Reassembly)            |
 |   - Autonomous Protocol Classification (SMTP: 25/587, IMAP: 143, POP3: 110)   |
 |   - STARTTLS State Machine Tracking: Advertised -> Command -> Response -> Upgr |
 |   - STRIPTLS Downgrade Detection: Advertised STARTTLS with Cleartext AUTH Fall |
 +---------------------------------------+----------------------------------------+
                                         |
                                         v
 +--------------------------------------------------------------------------------+
 |                          CRYPTOGRAPHIC ANALYSIS ENGINE                         |
 |   - TLS Record Layer & Handshake Parsing (ClientHello, ServerHello, Certs)     |
 |   - TLS Version Identification (SSL 2.0/3.0, TLS 1.0, 1.1, 1.2, TLS 1.3)       |
 |   - Comprehensive IANA Cipher Suite Resolution (PFS, AEAD, Key Length)         |
 |   - X.509 ASN.1 DER Certificate Decoding (Expiration, Key Size, Self-Signed)  |
 |   - Threat Intelligence & CVE Mapping: SWEET32, POODLE, BEAST, ROBOT, LOGJAM   |
 |   - Regulatory Auditing: NIST SP 800-52r2, PCI-DSS v4.0 (Req 4.2.1), CIS       |
 +---------------------------------------+----------------------------------------+
                                         |
                                         v
 +--------------------------------------------------------------------------------+
 |                       AI/ML HEURISTIC & RISK ENGINE                            |
 |   - 11-Dimensional Normalized Cryptographic Feature Vectorization              |
 |   - Unsupervised Anomaly Detection via Calibrated Isolation Forest             |
 |   - Explainable AI (XAI): Feature Variance Attribution & Human Justification   |
 |   - Quantitative Composite Risk Scoring (0 - 100) & Threat Severity Ranking   |
 +---------------------------------------+----------------------------------------+
                                         |
                                         v
 +--------------------------------------------------------------------------------+
 |                         PRESENTATION & REST API LAYER                          |
 |   - RESTful API Endpoints (FastAPI) for Automated SOC & CI/CD Ingestion        |
 |   - Interactive Dark-Themed Forensic HTML Reports & JSON Telemetry             |
 |   - SOC/DFIR Dashboard Visualization Schema & Compliance Radar Metrics         |
 +--------------------------------------------------------------------------------+
```

---

## 🔒 Authorship & Integrity Watermark

This project contains an embedded, tamper-evident cryptographic authorship signature:
* **Lead Architect & Developer:** `Ibrahim Ali`
* **Cryptographic Verification Digest:** `c4d51079f2e517acfecb5443ab0682566a58339e620259c401ec435e8fb453c3`
* **Integrity Enforcement:** The core framework dynamically verifies the cryptographic hash of the author watermark during runtime (`securemailscope.verify_framework_integrity()`). Any alteration, removal, or tampering with the authorship string immediately halts execution with an integrity violation.

---

## 🚀 Getting Started

### 1. Prerequisites
* Python 3.11 or higher
* Git

### 2. Installation
Clone the repository and initialize the Python virtual environment:

```bash
git clone <https://github.com/Operandnotfound/SSMS>
cd SIH

# Create virtual environment
python -m venv .venv

# Activate environment
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Verification & Automated Test Suite
Run the self-verification script to confirm environment integrity, module loading, and execute the automated test suite:

```bash
python build_all.py
```

All 4 test suites will execute:
* Modern AEAD cipher resolution with Perfect Forward Secrecy (PFS)
* Deprecated 3DES cipher and SWEET32 CVE vulnerability detection
* ASN.1 DER X.509 certificate decoding, key-length checking, and self-signed flags
* Multi-session synthetic PCAP pipeline with STARTTLS negotiation and STRIPTLS downgrade detection

---

## 🌐 RESTful API Endpoints

Launch the FastAPI service using Uvicorn:

```bash
uvicorn securemailscope.api:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI Swagger UI will be accessible at: `http://localhost:8000/docs`

### API Reference Table

| Method | Endpoint | Description | Security Controls |
|---|---|---|---|
| `GET` | `/api/v1/health` | Service health, ML readiness, and author watermark verification | Public probe |
| `POST` | `/api/v1/analyze/pcap` | Synchronous streaming PCAP upload & immediate forensic JSON report | 1 GiB size limit, streaming chunking, path traversal sanitization |
| `POST` | `/api/v1/analyze/pcap/async` | Asynchronous PCAP upload queueing for large files | Background worker task, tempfile auto-cleanup |
| `GET` | `/api/v1/jobs/{job_id}` | Poll asynchronous processing job status and results | Job ticket lookup |
| `GET` | `/api/v1/reports/{analysis_id}/html` | Render interactive, self-contained dark-mode forensic HTML report | XSS sanitized |
| `GET` | `/api/v1/reports/{analysis_id}/dashboard`| Retrieve aggregate metrics conforming to SOC/DFIR dashboard schema | Structured metrics |

---

## 📊 Sample Forensic Report (JSON Output)

```json
{
  "analysis_id": "b0a2cb96-d615-4f76-8809-562629b36eb6",
  "filename": "mail_capture.pcap",
  "file_size_bytes": 1048576,
  "analyzed_at": "2026-09-09T23:50:00Z",
  "total_sessions_parsed": 2,
  "encrypted_sessions_count": 1,
  "cleartext_sessions_count": 1,
  "downgrade_attacks_detected": 1,
  "average_risk_score": 52.5,
  "severity_breakdown": {
    "CRITICAL": 1,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "INFORMATIONAL": 1
  },
  "sessions": [
    {
      "session_id": "192.168.1.101:49153->10.0.0.25:587",
      "flow_tuple": "192.168.1.101:49153 -> 10.0.0.25:587",
      "protocol": "SMTP",
      "overall_risk_score": 88.5,
      "severity": "CRITICAL",
      "deterministic_penalty": 50.0,
      "ml_anomaly_score": 0.95,
      "anomaly_detected": true,
      "anomaly_explanations": [
        {
          "feature_name": "downgrade_detected",
          "observed_value": "Downgrade Detected",
          "baseline_reference": "No Downgrade",
          "contribution_weight": 0.42,
          "human_readable_reason": "STARTTLS negotiation was offered but bypassed/stripped, exposing credentials in cleartext."
        }
      ],
      "cve_associations": [
        "STARTTLS Stripping / Downgrade Attack Detected"
      ],
      "prioritized_remediations": [
        "[P1 - URGENT] Enforce MTA-STS and DANE (TLSA) to prevent STARTTLS stripping attacks.",
        "[P1 - URGENT] Reject plaintext authentication (AUTH) until TLS handshake is complete."
      ]
    }
  ]
}
```

---

## 🛡️ Security & Exploit Hardening

* **No Naked Keys or Backdoors:** Purely passive wire analysis without credentials or external remote code execution paths.
* **Path Traversal Defense:** Uploaded filenames are sanitized via `os.path.basename()`. File writes are strictly restricted to isolated, ephemeral files generated via `tempfile.mkstemp()`.
* **Resource Exhaustion (DoS) Mitigation:** Files are streamed in 1 MiB chunked buffers up to a maximum 1 GiB cap to prevent memory bloat and disk-fill attacks.
* **Deterministic Cleanup:** All temporary artifacts are bound within `try...finally` blocks with `os.unlink()`.
* **Zero Untrusted Deserialization:** The machine learning engine avoids `pickle.loads()` from external files by initializing baseline profiles programmatically in-memory.

---

## 📄 License & Attribution

Copyright (c) 2026 **Ibrahim Ali**. All rights reserved.  
Licensed under the [Apache License, Version 2.0](LICENSE).
