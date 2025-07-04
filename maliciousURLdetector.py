import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import re
import base64
import whois
import requests
from urllib.parse import urlparse
from domain_recon import check_domain_age
import subprocess
import sys

suspicious_tlds = {"xyz", "tk", "gq", "ml", "top", "cf", "ga"}
phishing_keywords = {"login", "secure", "update", "verify", "account", "bank", "signin","confirm"}
academic_gov_suffixes = (".gov", ".edu", ".gov.eg", ".edu.eg", ".gouv.fr", ".gov.uk", ".edu.sa", ".gov.au")

# --- Analysis Functions ---
def analyze_url_heuristics(url, output_func):
    output_func(f"\n🔍 Heuristic Analysis for URL: {url}\n", "header")
    parsed = urlparse(url)
    issues = []

    if not parsed.scheme or not parsed.netloc:
        output_func("❌ Invalid URL format.\n", "error")
        return

    hostname_parts = (parsed.hostname or "").split(".")

    # 1. IP address usage
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""):
        issues.append("Uses IP address instead of domain")

    # 2. Too many subdomains
    if len(hostname_parts) > 4:
        issues.append("Too many subdomains (possible obfuscation)")

    # 3. WHOIS check for newly created domains
    domain = parsed.hostname
    if domain:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            output_func("⚠️ WHOIS not applicable for IP addresses.\n", "warning")
        else:
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if not creation_date:
                    if any(domain.endswith(suffix) for suffix in academic_gov_suffixes):
                        output_func("📚 WHOIS data restricted — Academic or government domain.\n", "info")
                    else:
                        output_func("⚠️ Creation date not available — domain may be free, private, or misconfigured.\n",
                                    "warning")
                        if issues is not None:
                            issues.append("Domain has no WHOIS creation date and doesn't appear to be academic or government.")
                else:
                    output_func(f"\n📂 WHOIS creation date for {domain}: {creation_date}\n", "info")
                    check_domain_age(creation_date, issues, output_func)
            except Exception as e:
                if "No entries" in str(e) or "No match for" in str(e):
                    output_func("❌ Domain does not exist (not registered).\n",
                                "error")
                    if issues is not None:
                        issues.append("Domain is unregistered (potential phishing or spoofing attempt)")
                else:
                    output_func(f"❌ WHOIS check failed: {e}\n", "warning")

    # 4. Suspicious TLD
    tld = hostname_parts[-1] if len(hostname_parts) > 1 else ""
    if tld in suspicious_tlds:
        issues.append(f"Suspicious TLD: .{tld}")

    # 5. Punycode
    if "xn--" in (parsed.hostname or ""):
        issues.append("Uses punycode (possible homograph attack)")

    # 6. Suspicious keywords
    domain_and_path = f"{parsed.netloc}{parsed.path}".lower()
    for keyword in phishing_keywords:
        if keyword in domain_and_path:
            issues.append(f"Contains suspicious keyword: '{keyword}'")

    # 7. Obfuscation characters
    if "@" in url or "%" in url:
        issues.append("Contains obfuscation characters (@ or %)")

    if issues:
        output_func(f"\n⚠️ {len(issues)} potential red flags detected:\n", "warning")
        for i in issues:
            output_func(f"  - {i}\n", "warning")
    else:
        output_func("✅ URL appears clean based on heuristics.\n", "info")

def check_virustotal(url, api_key, output_func):
    output_func("\n🧪 VirusTotal Lookup...\n", "header")
    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"

    try:
        res = requests.post(scan_url, headers=headers, data={"url": url})
        if res.status_code != 200:
            if res.status_code == 400:
                output_func("❌ Invalid URL or request format. VirusTotal could not process this submission.\n", "error")
            elif res.status_code == 403:
                output_func("❌ Access denied. Check if your API key is valid and has permission.\n", "error")
            elif res.status_code == 429:
                output_func("❌ Rate limit exceeded. You’ve sent too many requests to VirusTotal. Try again later.\n",
                            "error")
            else:
                output_func(f"❌ Error submitting URL to VirusTotal: HTTP {res.status_code}\n", "error")
            return

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        report_url = f"{scan_url}/{url_id}"
        report_res = requests.get(report_url, headers=headers)

        if report_res.status_code != 200:
                if report_res.status_code == 404:
                    output_func("❌ Report not found. The URL may not have been analyzed by VirusTotal yet.\n", "error")
                elif report_res.status_code == 403:
                    output_func("❌ Access denied. Your API key might be restricted or invalid.\n", "error")
                elif report_res.status_code == 429:
                    output_func("❌ Too many requests. VirusTotal is rate-limiting your access. Try again later.\n",
                                "error")
                else:
                    output_func(f"❌ Failed to retrieve report: HTTP {report_res.status_code}\n", "error")
                return

        stats = report_res.json()["data"]["attributes"]["last_analysis_stats"]
        output_func(f"  - Malicious: {stats['malicious']}\n", "info")
        output_func(f"  - Suspicious: {stats['suspicious']}\n", "info")
        output_func(f"  - Harmless: {stats['harmless']}\n", "info")
        output_func(f"  - Undetected: {stats['undetected']}\n", "info")

        if stats['malicious'] > 0 or stats['suspicious'] > 0:
            output_func("⚠️ This URL appears to be unsafe.\n", "warning")
        else:
            output_func("✅ VirusTotal did not flag this URL.\n", "info")

    except Exception as e:
        output_func(f"❌ VirusTotal check failed: {e}\n", "error")

# --- GUI Actions ---
def run_analysis(vt_only=False):
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Input Error", "Please enter a URL.")
        return
    if not urlparse(url).scheme:
        url = "http://" + url    # default fallback

    if not vt_only:
        output_text.config(state='normal')
        output_text.delete(1.0, tk.END)
        output_text.config(state='disabled')

    loading_label.config(text="⏳ Checking URL..." if vt_only else "⏳ Analyzing URL...")
    analyze_btn.config(state='disabled')
    threading.Thread(target=perform_analysis, args=(url, vt_only), daemon=True).start()

def perform_analysis(url, vt_only=False):
    def output_func(text, tag="info"):
        output_text.config(state='normal')
        output_text.insert(tk.END, text, tag)
        output_text.see(tk.END)
        output_text.config(state='disabled')

    if not vt_only:
        analyze_url_heuristics(url, output_func)

    if vt_var.get():
        key = vt_key_entry.get().strip()
        vt_error_label.config(text="")
        if not key:
            vt_error_label.config(text="API key required for VirusTotal.")
            loading_label.config(text="")
            analyze_btn.config(state='normal')
            return
        if len(key) < 20:
            vt_error_label.config(text="API key looks too short to be valid. Please check and try again.")
            loading_label.config(text="")
            analyze_btn.config(state='normal')
            return
        check_virustotal(url, key, output_func)

    loading_label.config(text="")
    analyze_btn.config(state='normal')

def toggle_virustotal():
    if vt_var.get():
        vt_key_label.grid()
        vt_key_entry.grid()
        vt_error_label.grid()
    else:
        vt_key_label.grid_remove()
        vt_key_entry.grid_remove()
        vt_error_label.grid_remove()
        vt_error_label.config(text="")

def go_back():
    root.destroy()
    subprocess.Popen([sys.executable, "GUI.py"])


# --- GUI Setup ---
root = tk.Tk()
root.title("URL Scanner")
root.geometry("700x650")
root.config(bg="black")
top_frame = tk.Frame(root, bg="black")
top_frame.pack(anchor="nw", fill="x")

back_btn = tk.Button(top_frame, text="⬅ Back to Menu", font=("Segoe UI", 12),
                     bg="#444", fg="white", bd=0, padx=10, pady=5,
                     activebackground="#555", activeforeground="white",
                     command=go_back)
back_btn.pack(anchor="w", padx=10, pady=10)


tk.Label(root, text="🔗 URL Scanner", font=("Segoe UI", 24, "bold"), fg="#82b1ff", bg="black").pack(pady=15)

entry_frame = tk.Frame(root, bg="black")
entry_frame.pack(pady=(0, 10))
tk.Label(entry_frame, text="Enter URL:", font=("Segoe UI", 14), fg="#82b1ff", bg="black").pack(side=tk.LEFT, padx=(0, 10))

url_entry = tk.Entry(entry_frame, font=("Segoe UI", 14), width=40, bg="#101010", fg="#e3f2fd", insertbackground="#82b1ff")
url_entry.pack(side=tk.LEFT)
url_entry.bind("<Return>", lambda event: run_analysis())

analyze_btn = tk.Button(root, text="Run Analysis", font=("Segoe UI", 14, "bold"),
                        bg="#82b1ff", fg="white", activebackground="#82b1ff",
                        activeforeground="white", command=run_analysis)
analyze_btn.pack(pady=10)

vt_frame = tk.Frame(root, bg="black")
vt_frame.pack()

vt_var = tk.BooleanVar()

vt_checkbox = tk.Checkbutton(
    vt_frame, text="Check with VirusTotal", variable=vt_var,
    font=("Segoe UI", 12), fg="#ffcc80", bg="black", activebackground="black",
    command=lambda: toggle_virustotal(), selectcolor="black"
)
vt_checkbox.grid(row=0, column=0, sticky="w", pady=5)


vt_key_label = tk.Label(vt_frame, text="Enter API Key:", font=("Segoe UI", 12),
                        fg="#82b1ff", bg="black")
vt_key_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
vt_key_label.grid_remove()


vt_key_entry = tk.Entry(vt_frame, font=("Segoe UI", 12), width=50,
                        bg="#101010", fg="#e3f2fd", insertbackground="#82b1ff")
vt_key_entry.grid(row=2, column=0, pady=(2, 10))
vt_key_entry.bind("<Return>", lambda event: run_analysis(vt_only=True))
vt_key_entry.grid_remove()

vt_error_label = tk.Label(vt_frame, text="", font=("Segoe UI", 11, "italic"),
                          fg="#ef9a9a", bg="black")
vt_error_label.grid(row=3, column=0, sticky="w")
vt_error_label.grid_remove()

loading_label = tk.Label(root, text="", font=("Segoe UI", 12, "italic"), fg="#ffcc80", bg="black")
loading_label.pack()

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 12),
                                        bg="#101010", fg="#bbdefb", state='disabled')
output_text.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)

output_text.tag_config("info", foreground="#82b1ff")
output_text.tag_config("warning", foreground="#ffcc80")
output_text.tag_config("error", foreground="#ef9a9a")
output_text.tag_config("header", foreground="#4fc3f7", font=("Segoe UI", 16, "bold"))

if __name__ == "__main__":
   root.mainloop()
