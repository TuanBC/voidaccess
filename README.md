# VoidAccess

> **A self-hosted OSINT platform for dark web threat intelligence.**  
> Automate the entire investigation workflow from query refinement to relationship mapping in 13 autonomous pipeline steps.

<div align="center">
  <video src="./screenshots/how-it-works.mp4" width="100%" controls autoplay loop muted></video>
</div>

---

## ⚡ The OSINT Powerhouse
Commercial threat intelligence platforms often charge prohibitive annual fees for capabilities that can be run on private hardware. **VoidAccess** democratizes high-end dark web intelligence by providing an automated, end-to-end workflow:

- **Query Refinement**: Intelligent search term optimization using LLMs.
- **Multilingual Search**: Deep-web fan-out across English, Russian, and Chinese engines.
- **Entity Extraction**: Autonomous identification of wallets, IOCs, PGP keys, and more.
- **Relationship Mapping**: Dynamic graph generation from extracted data co-occurrence.
- **Structured Export**: STIX 2.1, MISP, Sigma, and CSV support.

---

## 🖼️ Visual Walkthrough

### 1. Intuitive Dashboard
Start investigations with a clean, dark-themed interface designed for high-stakes research.
![Homepage](./screenshots/homepage.png)

### 2. Intelligent Scoping
Refine queries and select investigation depth with precision.
![Topic Selection](./screenshots/topic_selection.png)

### 3. Real-time Pipeline Tracking
Monitor the 13-step autonomous pipeline as it crawls and extracts intelligence.
![Loading](./screenshots/loading.png)

### 4. Interactive Graph Intelligence
Explore connections between entities, onion sites, and threat actors in a dynamic, high-contrast graph.
![Node Selection](./screenshots/node_selection.png)

### 5. Comprehensive Intel Reports
Get structured summaries and actionable artifacts once the scan completes.
![Scan Completed](./screenshots/scan_completed.png)

---

## 🛠️ How It Works (The 13-Step Pipeline)

VoidAccess handles the complexity of dark web research through a rigorous sequence:

1. **LLM Query Refinement**: Optimizes search terms for .onion engine indexing.
2. **Global Fan-out Search**: Queries 16+ Tor engines across multiple languages.
3. **Intelligence Filtering**: LLM filters noise, keeping only relevant intelligence pages.
4. **Multi-Source Enrichment**: Pulls from AlienVault OTX, abuse.ch, ransomware.live, CISA KEV, and Shodan.
5. **Recursive .onion Discovery**: Discovers hidden links via seed URL crawling.
6. **Vector Cache Check**: Avoids redundant scraping for recently visited pages.
7. **Tor-Routed Scraping**: Safely fetches page content with a 1MB safety cap.
8. **Persistence**: Stores new content in the local vector cache.
9. **Intelligence Merging**: Combines scraped and enriched data for processing.
10. **Advanced Extraction**: Regex, NER, and LLM-based entity identification.
11. **Historical Cross-Referencing**: Validates data against seed datasets.
12. **Graph Construction**: Builds relationship nodes based on co-occurrence.
13. **Final Intelligence Summary**: LLM generates a structured technical briefing.

---

## 🔌 LLM & Enrichment Ecosystem

### Supported LLM Providers:
- **Cloud**: OpenRouter (DeepSeek, Llama 3.3), OpenAI, Anthropic, Google Gemini.
- **Local**: Ollama (Air-gapped, no API key required).

### Enrichment Sources:
- **AlienVault OTX**, **MalwareBazaar**, **ThreatFox**, **URLhaus**.
- **ransomware.live**, **CISA KEV**, **Shodan InternetDB**, **VirusTotal**.

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Tor-capable network
- One LLM API key (or Ollama for local-only)

### Installation
```bash
cp .env.example .env
bash setup.sh
```
The setup wizard will guide you through provider selection and credential setup.

---

## ⚖️ Acceptable Use
VoidAccess is intended for authorized security research, threat intelligence gathering, and law enforcement purposes only. Users are responsible for ensuring compliance with all local laws and ethical standards.

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.