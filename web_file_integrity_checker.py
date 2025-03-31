
import streamlit as st
import requests
import hashlib
import json
import concurrent.futures
from datetime import datetime, timezone
from io import BytesIO

# ---------- Secure API Key Input ----------
st.set_page_config(page_title="Web File Integrity Checker", layout="wide")
st.title("🛡️ Web File Integrity Checker")

# ---------- App Description ----------
st.markdown("""
This tool helps you monitor the integrity of externally hosted files such as JavaScript SDKs or configuration files
by scanning subdomains and checking for the presence and integrity of a specific file.

**Use cases include:**
- Monitoring third-party payment SDKs
- Verifying consistent deployment of scripts across environments
- Detecting unexpected changes or tampering

🔑 **API Access**:  
Enter your [SecurityTrails](https://securitytrails.com/) API key in the sidebar.  
Your key is **not stored, logged, or transmitted** beyond this session. It is only used for discovery.
""")

# ---------- Sidebar API Input ----------
st.sidebar.header("🔐 API Access")
if "api_key" not in st.session_state:
    st.session_state.api_key = ""

api_input = st.sidebar.text_input(
    "Enter your SecurityTrails API key",
    type="password",
    placeholder="sk_xxxxxx...",
    help="This key is used only for this session and not stored."
)

if api_input:
    st.session_state.api_key = api_input

# ---------- Subdomain Discovery ----------
def get_subdomains(domain):
    SECURITYTRAILS_API_KEY = st.session_state.get("api_key", "")
    if not SECURITYTRAILS_API_KEY:
        st.error("SecurityTrails API key not set. Please enter it in the sidebar.")
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "Accept": "application/json",
        "APIKEY": SECURITYTRAILS_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            raise ValueError(f"SecurityTrails API error (status: {resp.status_code})")
        data = resp.json()
        subdomains = data.get("subdomains", [])
        full_domains = [f"{sub}.{domain}" for sub in subdomains]
        return sorted(full_domains)
    except Exception as e:
        st.error(f"Error fetching subdomains from SecurityTrails: {e}")
        return []

# ---------- Utilities ----------
def fetch_and_hash(subdomain, path, mime_filter):
    headers = {"User-Agent": "Mozilla/5.0"}
    for scheme in ["https://", "http://"]:
        try:
            url = f"{scheme}{subdomain}{path}"
            r = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            content_type = r.headers.get("Content-Type", "")
            if r.status_code == 200 and mime_filter in content_type:
                content_hash = hashlib.sha3_256(r.content).hexdigest()
                return {
                    "domain": subdomain,
                    "path": path,
                    "mime_type": content_type,
                    "hash": content_hash,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
        except requests.RequestException:
            continue
    return {"domain": subdomain, "status": "not_found"}

def download_json(data):
    json_str = json.dumps(data, indent=2)
    b = BytesIO()
    b.write(json_str.encode())
    b.seek(0)
    return b

def generate_log(final_output, added, removed, changed, unchanged):
    summary = final_output["comparison_summary"]
    lines = [
        f"Scan Timestamp: {final_output['timestamp']}",
        f"Base Domain: {final_output['base_domain']}",
        f"File Path: {final_output['path']}",
        f"MIME Type: {final_output['mime_type']}",
        "",
        f"Original Domains: {summary['original_domains']}",
        f"Active Domains: {summary['active_domains']}",
        f"New Domains: {summary['new_domains']}",
        f"Changed: {summary['changed']}",
        f"Unchanged: {summary['unchanged']}",
        f"Removed: {summary['removed']}",
        ""
    ]
    if added:
        lines.append("New Domains Found:")
        lines.extend(f"  - {d}" for d in sorted(added))
    if removed:
        lines.append("\nRemoved Domains:")
        lines.extend(f"  - {d}" for d in sorted(removed))
    if changed:
        lines.append("\nChanged Domains:")
        lines.extend(f"  - {d}" for d in sorted(changed))
    if unchanged:
        lines.append("\nUnchanged Domains:")
        lines.extend(f"  - {d}" for d in sorted(unchanged))

    b = BytesIO()
    b.write("\n".join(lines).encode())
    b.seek(0)
    return b

# ---------- Tabs ----------
scan_tab, compare_tab = st.tabs(["📡 Baseline Scan", "🔍 Compare Scans"])

with scan_tab:
    st.header("Create Baseline Scan")
    domain_input = st.text_input("Enter the base domain:")
    path_input = st.text_input("Enter the file path to check:")
    mime_type = st.selectbox("Select MIME type to match:", [
        "application/javascript", "application/json", "text/javascript",
        "text/plain", "application/octet-stream"
    ])

    if st.button("Run Scan"):
        if not domain_input or not path_input:
            st.warning("Please enter both domain and path.")
        else:
            st.info("Fetching subdomains and scanning... This may take a moment.")
            subdomains = get_subdomains(domain_input)
            results = []
            with st.spinner("Scanning domains..."):
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = {
                        executor.submit(fetch_and_hash, sub, path_input, mime_type): sub for sub in subdomains
                    }
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res and res.get("status") != "not_found":
                            results.append(res)

            output = {
                "scan_type": "baseline",
                "domain_input": domain_input,
                "path": path_input,
                "mime_type": mime_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "scanned_domains": subdomains,
                "matched_results": results
            }

            st.success(f"Baseline scan complete! {len(results)} domains responded with the file.")
            st.download_button(
                label="📅 Download JSON Results",
                data=download_json(output),
                file_name=f"scan_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
            st.json(output)

with compare_tab:
    st.header("Compare with Previous Scan")
    uploaded_file = st.file_uploader("Upload previous JSON scan file:", type="json")
    if uploaded_file is not None:
        previous_data_full = json.load(uploaded_file)
        previous_data = previous_data_full.get("matched_results", [])
        st.write(f"Loaded {len(previous_data)} matched records from previous scan.")

        base_domain = previous_data_full.get("domain_input", "")
        path = previous_data_full.get("path", "/")
        mime_type = previous_data_full.get("mime_type", "application/javascript")

        previous_domains = {entry['domain'] for entry in previous_data}
        previous_hash_map = {entry['domain']: entry['hash'] for entry in previous_data}

        st.info("Rechecking original domains from previous scan...")
        current_results = []
        with st.spinner("Re-scanning original domains..."):
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(fetch_and_hash, domain, path, mime_type): domain for domain in previous_domains
                }
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res:
                        current_results.append(res)

        current_hash_map = {entry['domain']: entry['hash'] for entry in current_results if 'hash' in entry}
        current_domains = {entry['domain'] for entry in current_results if 'hash' in entry}

        added = set()
        removed = previous_domains - current_domains
        unchanged = []
        changed = []

        for domain in current_domains & previous_domains:
            if previous_hash_map.get(domain) == current_hash_map.get(domain):
                unchanged.append(domain)
            else:
                changed.append(domain)

        st.info("Looking for new domains via SecurityTrails...")
        new_domains = set(get_subdomains(base_domain)) - previous_domains - current_domains
        new_scan_results = []
        with st.spinner("Scanning for new domains..."):
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {
                    executor.submit(fetch_and_hash, domain, path, mime_type): domain for domain in new_domains
                }
                for future in concurrent.futures.as_completed(futures):
                    res = future.result()
                    if res and res.get("status") != "not_found":
                        new_scan_results.append(res)
                        added.add(res['domain'])

        st.subheader("Comparison Results Summary")
        st.write({
            "original_domains": len(previous_domains),
            "active_domains": len(current_domains),
            "new_domains": len(added),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "removed": len(removed),
        })

        final_output = {
            "scan_type": "comparison",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "base_domain": base_domain,
            "path": path,
            "mime_type": mime_type,
            "comparison_summary": {
                "original_domains": len(previous_domains),
                "active_domains": len(current_domains),
                "new_domains": len(added),
                "changed": len(changed),
                "unchanged": len(unchanged),
                "removed": len(removed),
            },
            "new_results": new_scan_results,
            "rechecked_results": current_results
        }

        st.download_button(
            label="📅 Download Updated JSON",
            data=download_json(final_output),
            file_name=f"scan_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

        st.download_button(
            label="📄 Download Log File",
            data=generate_log(final_output, added, removed, changed, unchanged),
            file_name=f"scan_log_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )
