import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import dns.resolver
import requests
import whois
from datetime import datetime
import re
import socket
import subprocess
import sys


# --- Domain validation & functions ---
def is_valid_domain(domain):
    return re.match(r"^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,}$", domain)

def check_domain_age(creation_date, issues=None, output_func=None):
    try:
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            output_func(f"🧮 Domain Age: {age_days} days\n", "info")
            if age_days < 180:
                output_func("⚠️ This is a newly registered domain — could be suspicious.\n", "warning")
                if issues is not None:
                    issues.append(f"Newly registered domain ({age_days} days old)")
        else:
            output_func("⚠️ Creation date not available.\n", "warning")
    except Exception as e:
        output_func(f"❌ Failed to calculate domain age: {e}\n", "error")


def get_whois_info(domain, output_func):
    try:
        socket.setdefaulttimeout(10)
        w = whois.whois(domain)
        if w.domain_name is None:
            output_func("⚠️ WHOIS data not available for this domain (possibly government or academic domain).\n", "warning")
            return

        output_func("\nWHOIS Information:\n", "header")
        output_func(f"Domain: {w.domain_name}\n", "info")
        output_func(f"Registrar: {w.registrar}\n", "info")
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        output_func(f"Creation Date: {creation_date}\n", "info")
        output_func(f"Expiry Date: {expiration_date}\n", "info")
        check_domain_age(creation_date, output_func=output_func)

    except socket.timeout:
        output_func("❌ WHOIS lookup timed out. Check your internet connection and try again.\n", "error")
    except Exception as e:
        if "No match for" in str(e):
            output_func("❌ Domain does not exist (not registered). Please check domain name and try again.\n", "error")
        elif "getaddrinfo failed" in str(e):
            output_func("❌ WHOIS lookup timed out. Please check your connection and try again.\n", "error")
        else:
            output_func(f"❌ WHOIS lookup failed: {e}\n", "error")

def geolocate_ip(ip, output_func):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if res.status_code != 200:
            output_func(f"  [x] Failed to geolocate {ip} (status code {res.status_code})\n", "error")
            return
        data = res.json()
        output_func("  🌍 Geolocation:\n", "header")
        output_func(f"    IP: {data.get('ip')}\n", "info")
        output_func(f"    Country: {data.get('country')}\n", "info")
        output_func(f"    Org: {data.get('org')}\n", "info")
        output_func(f"    ASN: {data.get('asn', {}).get('asn') if 'asn' in data else 'N/A'}\n\n", "info")
    except Exception as e:
        output_func(f"  [x] Failed to geolocate {ip}: {e}\n", "error")

def get_dns_records(domain, output_func):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    output_func("\nDNS Records:\n", "header")

    # Early check for NXDOMAIN
    try:
        dns.resolver.resolve(domain, 'A', lifetime=5)
    except dns.resolver.NXDOMAIN:
        output_func("❌ DNS error: Domain does not exist or cannot be resolved.\n", "error")
        return
    except dns.resolver.Timeout:
        output_func("❌ DNS resolution timed out. Please check your connection and try again.\n", "error")
        return
    except Exception as e:
        output_func(f"⚠️ DNS pre-check error: {e}\n", "warning")
        return

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            output_func(f"\n{rtype} Records:\n", "header")
            for answer in answers:
                output_func(f"  {answer.to_text()}\n", "info")
                if rtype in ['A', 'AAAA']:
                    geolocate_ip(answer.to_text(), output_func)
        except dns.resolver.NoAnswer:
            output_func(f"  No {rtype} record found.\n", "warning")
        except dns.resolver.Timeout:
            output_func(f"  Timeout retrieving {rtype} record. Check your connection.\n", "warning")
        except Exception as e:
            output_func(f"  Error retrieving {rtype} record: {e}\n", "error")


# --- GUI Functions ---

def launch_gui():

    def go_back():
        root.destroy()
        subprocess.Popen([sys.executable, "GUI.py"])

    def run_analysis():
        domain = domain_entry.get().strip()
        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain name.")
            return
        if '.' not in domain:
            domain += ".com"  # default fallback

        if not is_valid_domain(domain):
            messagebox.showerror("Invalid Domain", "Please enter a valid domain format.")
            return
        output_text.config(state='normal')
        output_text.delete(1.0, tk.END)
        output_text.config(state='disabled')

        loading_label.config(text="⏳ Fetching DNS records... please wait.")
        threading.Thread(target=perform_analysis, args=(domain,), daemon=True).start()

    def perform_analysis(domain):
        def output_func(text, tag="info"):
            output_text.config(state='normal')
            output_text.insert(tk.END, text, tag)
            output_text.see(tk.END)
            output_text.config(state='disabled')

        output_func(f"Analyzing domain: {domain}\n\n", "header")
        get_whois_info(domain, output_func)
        get_dns_records(domain, output_func)
        loading_label.config(text="")

    # --- Setup GUI ---
    root = tk.Tk()
    root.title("Domain Recon Tool")
    root.geometry("700x650")
    root.config(bg="black")
    top_frame = tk.Frame(root, bg="black")
    top_frame.pack(fill="x", anchor="nw")

    back_btn = tk.Button(top_frame, text="⬅ Back to Menu", font=("Segoe UI", 12),
                         bg="#444", fg="white", bd=0, padx=10, pady=5,
                         activebackground="#555", activeforeground="white",
                         command=go_back)
    back_btn.pack(side="left", padx=10, pady=10)

    header_label = tk.Label(root, text="🔍 Domain Recon Tool", font=("Segoe UI", 24, "bold"), fg="#82b1ff", bg="black")
    header_label.pack(pady=15)

    entry_frame = tk.Frame(root, bg="black")
    entry_frame.pack(pady=(0, 10))

    domain_label = tk.Label(entry_frame, text="Enter Domain:", font=("Segoe UI", 14), fg="#82b1ff", bg="black")
    domain_label.pack(side=tk.LEFT, padx=(0, 10))

    domain_entry = tk.Entry(entry_frame, font=("Segoe UI", 14), width=40, bg="#101010", fg="#e3f2fd",
                            insertbackground="#82b1ff")
    domain_entry.pack(side=tk.LEFT)
    domain_entry.bind("<Return>", lambda event: run_analysis())

    analyze_btn = tk.Button(root, text="Run Analysis", font=("Segoe UI", 14, "bold"),
                            bg="#82b1ff", fg="white", activebackground="#82b1ff",
                            activeforeground="white", command=run_analysis)
    analyze_btn.pack(pady=10)

    loading_label = tk.Label(root, text="", font=("Segoe UI", 12, "italic"), fg="#ffcc80", bg="black")
    loading_label.pack(pady=(0, 5))

    output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 12),
                                            bg="#101010", fg="#bbdefb", state='disabled')
    output_text.pack(expand=True, fill=tk.BOTH, padx=15, pady=15)

    output_text.tag_config("info", foreground="#82b1ff")
    output_text.tag_config("warning", foreground="#ffcc80")
    output_text.tag_config("error", foreground="#ef9a9a")
    output_text.tag_config("header", foreground="#4fc3f7", font=("Segoe UI", 16, "bold"))
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
