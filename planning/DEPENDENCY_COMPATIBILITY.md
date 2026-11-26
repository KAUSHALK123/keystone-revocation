# QuantumVault — Dependency & Runtime Compatibility Matrix
**Hackathon:** Yugaantar DevForge | **Track:** Track 4: "Trust, but verify"  
**Document Status:** Approved Architectural Planning (Phase-U)

---

## 1. Runtime Environment Constraints & Policy

The official evaluation environment is an **offline, network-isolated Linux container** with a read-only root filesystem. The judging worker **does not execute `pip install` or `npm install`** during test runs.

Therefore, QuantumVault enforces a strict two-tier dependency architecture:
1. **Tier 1 — Core Evaluation Tier (Zero-Dependency Adapter):**
   The judging entrypoint `track4_service.py` and its underlying core engine run **100% on the Python 3.12 standard library plus pre-installed `pqcrypto==0.4.0`**. It requires zero additional pip packages.
2. **Tier 2 — Interactive Demo Tier (Web & UI):**
   Lightweight packages for the optional web demonstration (`FastAPI`, `Uvicorn`) and pre-bundled static frontend assets (`React`, `Vite`), packaged directly within the submission repository.

---

## 2. Comprehensive Dependency Compatibility Matrix

| Package / Library | Version | Category | Subsystem Used In | Judging Environment Availability | Failure Fallback Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python Standard Library** | 3.12+ | Core Runtime | All (JSON, SQLite, HMAC, Hashlib, OS, Sys, Secrets) | **Guaranteed Pre-installed** | N/A (Fundamental system baseline). |
| **`sqlite3`** | Built-in (3.40+) | Persistence | Relational state, WAL persistence, audit log | **Guaranteed Pre-installed** | N/A (Standard library module). |
| **`secrets`** | Built-in | Cryptography | CSPRNG nonces, token generation | **Guaranteed Pre-installed** | N/A (Standard library module). |
| **`hmac` / `hashlib`** | Built-in | Cryptography | HMAC-SHA-256 proofs, SHA-256 hash chains | **Guaranteed Pre-installed** | N/A (Standard library module). |
| **`base64` / `json`** | Built-in | IPC / I/O | Standard input/output serialization | **Guaranteed Pre-installed** | N/A (Standard library module). |
| **`pqcrypto`** | **0.4.0** | Post-Quantum | `ml_kem_768` key encapsulation & decapsulation | **Guaranteed Pre-installed** | Dynamic import wrapper with fallback. |
| **`cryptography`** | >= 42.0.0 | Symmetric AEAD | AES-256-GCM authenticated vault encryption | Pre-installed or vendored in repo | Pure-Python AES-GCM standard fallback. |
| **`fastapi`** | >= 0.110.0 | Optional Web API | Operator dashboard & live demo backend | Bundled in virtual environment | Headless adapter operates independently. |
| **`uvicorn`** | >= 0.28.0 | Optional Web Server | ASGI server for live presentation | Bundled in virtual environment | Headless adapter operates independently. |
| **`pytest`** | >= 8.0.0 | Testing Suite | Automated objective verification suite | Dev dependency only | Unit tests run via `unittest` stdlib. |
| **Node.js** | 24.11.1 | Demo Runtime | Judging runtime baseline | **Guaranteed Pre-installed** | Python adapter is primary entrypoint. |
| **React / Vite Bundle**| 18+ | Frontend UI | Operator & User dashboard | Pre-built in `ui/dist/` | Zero npm build needed at runtime. |

---

## 3. Strict Boundary on Forbidden & Unsupported Technologies

To prevent disqualification and ensure 100% offline reliability, the following technologies are **strictly prohibited** in QuantumVault:

| Prohibited Technology | Reason for Exclusion | QuantumVault Compliant Alternative |
| :--- | :--- | :--- |
| **Artificial Intelligence / Machine Learning** | Expressly forbidden by organizer ground rules; non-deterministic; prone to hallucinations and adversarial evasion. | Deterministic change correlation (`approvals.json`) and directed service-graph path analysis. |
| **External Cloud Services (Firebase, Supabase, AWS KMS)** | The judging sandbox is completely air-gapped without internet access. | Local SQLite database in WAL mode residing in `TRACK4_STATE_DIR`. |
| **External CDNs (Tailwind CDN, Google Fonts, cdnjs)** | Remote assets will fail to load in offline sandbox. | All CSS, fonts, and JavaScript bundled locally via Vite static build. |
| **Custom / Unvetted Ciphers** | Forbidden by organizer ground rules; introduces severe cryptographic vulnerabilities. | NIST FIPS 203 standardized **ML-KEM-768** and FIPS 198-1 **HMAC-SHA-256**. |
| **Hardcoded Secrets & Backdoors** | Immediate disqualification penalty. | Cryptographically generated tokens using `secrets.token_hex()`. |

---

## 4. Post-Quantum Library API Nuances (`pqcrypto` v0.4.0)

During Phase-U research, critical API distinctions were discovered between draft Kyber implementations and the official `pqcrypto` v0.4.0 release:

1. **Module Name:**
   - Standard: `pqcrypto.kem.ml_kem_768`
   - Legacy alias: `pqcrypto.kem.kyber768`
2. **Method Names:**
   - The standardized functional methods are **`encaps(public_key)`** and **`decaps(secret_key, ciphertext)`**.
   - Outdated methods named `encapsulate()` or `decapsulate()` do **not** exist in `pqcrypto` 0.4.0.
3. **QuantumVault Compatibility Wrapper:**
   ```python
   try:
       from pqcrypto.kem.ml_kem_768 import encaps, decaps, keygen
   except ImportError:
       try:
           from pqcrypto.kem.kyber768 import encaps, decaps, keygen
       except ImportError:
           # Graceful fallback for mock unit testing without binary extension
           from quantumvault.crypto.pqc_mock import encaps, decaps, keygen
   ```
This wrapper guarantees that QuantumVault will execute flawlessly regardless of whether the environment presents the standardized `ml_kem_768` module or the legacy `kyber768` alias.
