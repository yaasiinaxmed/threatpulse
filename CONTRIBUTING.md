# Contributing to ThreatPulse ⚡

Thank you for your interest in improving ThreatPulse! We welcome contributions from developers, detection engineers, and cybersecurity professionals.

---

## 🚀 Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/<your-username>/threatpulse.git
   cd threatpulse
   ```
3. **Create a virtual environment & install dependencies**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

---

## 🛠️ Contribution Guidelines

### Adding a New Threat Feed Collector
1. Create a new collector module under `src/threatpulse/collectors/<feed_name>.py`.
2. Follow async patterns using `httpx.AsyncClient`.
3. Normalize indicators into the standard `IPIndicator` model.
4. Export the function in `src/threatpulse/collectors/__init__.py`.
5. Add unit tests for the collector in `tests/`.

### Proposing Safe-listed Ranges
If legitimate public cloud or DNS provider ranges are incorrectly flagged:
1. Propose updates in [`allowlist.txt`](allowlist.txt).
2. Include official documentation or ASN records proving legitimate ownership.

### Code Style & Quality
- Write type annotations and ensure clean formatting (`black` / `ruff`).
- Run the test suite before submitting:
  ```bash
  pytest -v
  ```

---

## 📬 Submitting a Pull Request (PR)

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Commit your changes:
   ```bash
   git commit -m "feat(collector): add emerging threats feed"
   ```
3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
4. Open a Pull Request against `yaasiinaxmed/threatpulse:main`.
