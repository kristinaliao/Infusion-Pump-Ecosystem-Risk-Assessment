# Wireless Infusion Pump Attack Graph & Security Engine

This project provides a simulation environment for analyzing the security posture of wireless infusion pump ecosystems within hospital networks. It uses a Hierarchical Attack Representation Model (HARM) approach to map vulnerabilities to network topologies, calculate multi-dimensional risk scores tailored to patient safety, and recommend optimized mitigation strategies for clinical environments.

## Core Features

### 1. Dynamic Infusion Pump Vulnerability Integration
The `vulnerability_builder.py` script automatically queries the **NVD (NIST) API v2.0** to fetch real-world CVE data based on Common Platform Enumeration (CPE) strings for specific infusion pumps (e.g., Alaris, Agilia, Prismaflex) and clinical gateways. It builds a localized library (`data/vulnerability_library.json`) containing impact scores, exploit complexity, and target device mappings.

### 2. Clinical Risk Scoring Model
Unlike traditional IT-centric models, this engine implements a safety-aware scoring system designed for medical device ecosystems:
**NodeRisk = CVSS_Impact × Exploitability × Criticality × Exposure**
- **Criticality:** Prioritizes life-critical devices (e.g., Infusion Pumps = 2.0) over peripheral support systems (e.g., Enterprise Servers = 1.0).
- **Exposure:** Reflects the device's placement in the network (e.g., Internet-facing = 2.0, Isolated Medical Zone = 1.0).

### 3. Mitigation Recommendation Engine
- **Patch Priority:** Identifies which pump or gateway vulnerabilities to patch first by measuring the cumulative reduction in total network risk to the infusion pump target.
- **Segmentation Recommendations:** Identifies risky network connections that, if blocked, would most effectively isolate the infusion pump ecosystem from external or enterprise-level threats.

### 4. Automated Security Experiments
The project includes a suite of experiments to validate security hypotheses regarding hospital network design and the efficiency of various patching strategies for protecting infusion pumps.

---

## Project Structure

```text
/
├── data/
│   └── vulnerability_library.json   # Generated infusion pump CVE data
├── src/
│   ├── security_engine.py          # Core logic for clinical risk analysis
│   ├── run_experiments.py          # Automated experiment runner
│   ├── topo_flat.py                # Mininet definition (Legacy/Reference)
│   └── topo_segmented.py           # Mininet definition (Legacy/Reference)
├── topologies/
│   ├── flat.json                   # Scaled Flat Network (Clinic-style)
│   └── segmented.json              # Scaled Segmented Network (NIST-compliant)
└── vulnerability_lib/
    └── vulnerability_builder.py    # NVD API Integration script
```

---

## Setup & Usage

### Prerequisites
- Python 3.10+
- `networkx` library
- `requests` library

### 1. Build the Vulnerability Library
To fetch the latest CVE data for medical devices from NIST:
```bash
python3 vulnerability_lib/vulnerability_builder.py
```

### 2. Analyze the Infusion Pump Attack Surface
Analyze a specific topology and target a specific pump (e.g., `pump_icu_1`):
```bash
python3 src/security_engine.py --topo segmented --target pump_icu_1
```

### 3. Run Experiments
Execute the experimental suite to compare protection strategies for infusion pumps:
```bash
python3 src/run_experiments.py
```

---

## Experimental Findings for Infusion Pump Security

### Experiment 1: Ecosystem Segmentation
**Result:** Segmenting the hospital network into distinct zones (following NIST SP 1800-8) reduced the risk to infusion pumps by **~86%** and limited the number of viable attack paths from 15 down to 4.

### Experiment 2: Patching Strategy Efficiency
**Result:** The **Risk-Reduction Optimizer** strategy significantly outperformed random and "Highest CVSS" patching. By targeting nodes that lie on multiple high-risk paths to the infusion pumps, residual risk was reduced far more effectively per patch applied.

### Experiment 3: Criticality Awareness
**Result:** By introducing Clinical Criticality multipliers, the engine successfully re-prioritized infusion pump vulnerabilities over generic enterprise vulnerabilities (like those on admin PCs) that might have higher raw CVSS scores but lower patient safety impact.
