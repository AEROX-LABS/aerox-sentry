# aerox-sentry — Automated Media Metadata & Geolocation Sanitizer

[![CI/CD Pipeline](https://github.com/aerox/aerox-sentry/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/aerox/aerox-sentry/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**aerox-sentry** is a high-performance privacy sentinel service engineered to inspect, catalog, and neutralize hidden metadata and geolocation vectors in media assets before public release or downstream storage.

---

## Problem Statement

Digital cameras and smartphones embed rich, invisible Exchangeable Image File Format (EXIF) headers into photos and media files. Unsanitized media uploads frequently leak sensitive vectors:

- **Precise Geolocation (GPS)**: Exact latitude, longitude, altitude, and bearing coordinates exposing residences, workplaces, and sensitive operational facilities.
- **Hardware & Device Fingerprints**: Camera make, lens models, device serial numbers, and software builds that can uniquely fingerprint individuals and hardware ecosystems.
- **Temporal Footprints**: High-precision timestamps (creation, digitized, and offset dates) allowing correlation across distinct user activities.

**aerox-sentry** mitigates these risks by actively intercepting media ingestion, performing automated EXIF analysis, indexing privacy threat levels, and reconstructing sanitized image buffers stripped of all metadata headers.

---

## Core Features

- **Deep EXIF Extraction**: Comprehensive parsing of primary IFD, SubIFD, and GPSInfo blocks via Pillow.
- **Buffer-Level Data Stripping**: In-memory pixel rasterization that discards all metadata segments without writing uncleaned artifacts to disk.
- **Automated Threat Rating**:
  - `High: Geolocation Exposed` — Direct coordinate and GPS telemetry discovered.
  - `Medium: Device/Timestamp Exposed` — Camera serials, hardware specifications, or timestamps identified.
  - `Safe (No EXIF)` — Clean asset free from privacy headers.
- **Real-Time Audit Ledger**: In-memory session tracking documenting every sanitized asset and neutralized threat.
- **Cloud-Native Probes**: Containerized health checks and commit-aware status endpoints for CI/CD orchestrators.

---

## Pipeline Architecture

Every code revision is validated through a multi-stage GitHub Actions pipeline before reaching production:

```
[ Git Push / PR to main ]
          │
          ▼
┌───────────────────────────────┐
│ Stage 1: lint-and-test        │
│ • Flake8 PEP 8 enforcement    │
│ • Pytest test suite           │
└──────────────┬────────────────┘
               │ (Pass)
               ▼
┌───────────────────────────────┐
│ Stage 2: build-and-smoke-test │
│ • Docker container build      │
│ • Local container spin-up     │
│ • /health endpoint probe      │
└──────────────┬────────────────┘
               │ (Pass & Push to main)
               ▼
┌───────────────────────────────┐
│ Stage 3: deploy               │
│ • Render Deploy Hook Trigger  │
│ • Zero-downtime rolling update│
└───────────────────────────────┘
```

---

## Local Setup & Development

### Prerequisites

- Python 3.9+ (or Python 3.12 recommended)
- Docker (optional, for containerization)

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/aerox/aerox-sentry.git
cd aerox-sentry

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Quality Checks & Test Suite

```bash
# Run Flake8 linter
flake8 .

# Run Pytest suite with verbose reporting
pytest -v
```

### 3. Launch Development Server

```bash
python app.py
```
Open [http://localhost:5000](http://localhost:5000) in your browser.

### 4. Run via Docker

```bash
# Build container image
docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD) -t aerox-sentry:latest .

# Run container
docker run -p 5000:5000 --name aerox-sentry aerox-sentry:latest

# Verify health check
curl http://localhost:5000/health
```

---

## API Specification

| Endpoint | Method | Description | Response Example |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | Service liveness probe and active commit identification | `{"commit": "d28f34a", "service": "aerox-sentry", "status": "ok"}` |
| `/api/audits` | `GET` | Complete ledger of all analyzed and sanitized files | `[{"id": 1, "filename": "shot.jpg", "threat_level": "Safe (No EXIF)", "has_gps": false, ...}]` |
| `/scrub` | `POST` | Multipart upload form endpoint (`photo` field) | Redirects (`302`) to `/` on success; returns `400` / `500` JSON on error |
| `/api/scrub` | `POST` | Programmatic multipart upload (`file` or `photo`) | Returns sanitized audit record JSON |

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
