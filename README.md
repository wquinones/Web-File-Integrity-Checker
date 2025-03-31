# 🛡️ Web File Integrity Checker

This Streamlit-powered app helps you monitor and verify the integrity of externally hosted files (e.g., JavaScript SDKs) across your web domain's subdomains.

Built for PCI-DSS v4.0.1 compliance (requirement 11.6.1), the tool allows you to:
- Automatically discover subdomains using the SecurityTrails API
- Download and hash specific file paths for integrity verification
- Create a cryptographic baseline (SHA3-256) of hosted scripts
- Compare new scans to previous results and highlight changes
- Download evidence in JSON and human-readable log formats

---

## 🔧 Features

- Subdomain discovery via SecurityTrails
- MIME-type filtering (e.g., JavaScript, JSON, plain text)
- SHA3-256 file integrity checking
- Visual and color-coded comparison results
- No storage of sensitive API credentials
- Lightweight and portable — runs anywhere with Python and Streamlit

---

## 📦 Requirements

Install dependencies using pip:

```bash
pip install -r requirements.txt
```

Then run the app:

```bash
streamlit run web_file_integrity_checker.py
```

---

## 🔐 SecurityTrails API Key

You'll be prompted to enter your [SecurityTrails](https://securitytrails.com/) API key in the sidebar UI.

- **It is NOT stored, logged, or transmitted beyond the session**
- Used only for querying subdomains

---

## 📁 Output Files

- `scan_results_YYYYMMDD_HHMMSS.json`: Baseline or comparison scan results
- `scan_log_YYYYMMDD_HHMMSS.txt`: Log file summarizing scan comparisons

---

## 📌 Use Cases

- Monitor hosted payment SDKs for tampering
- Detect unexpected changes in external scripts
- Verify consistency across dev, staging, and prod

---

## 📄 License

MIT License. Use at your own risk. Contributions welcome!
