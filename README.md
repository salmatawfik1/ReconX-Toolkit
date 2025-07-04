🛡️ ReconX Toolkit:
- ReconX Toolkit is a lightweight cybersecurity tool designed to analyze domains and URLs for potential threats using a combination of heuristic techniques, WHOIS lookups, DNS records, IP geolocation, and VirusTotal integration.
- Built with Python & Tkinter | Ideal for cybersecurity learners, bug bounty hunters, and OSINT tasks.

🚀 Features:

1- 🌐 Domain Recon Tool
 - WHOIS Information (Creation/Expiry Date, Registrar, Domain Age)
 - DNS Record Fetching (A, AAAA, MX, NS, TXT)
 - Geolocation for IP Addresses
 - Domain Age Analysis

2- 🔗 Malicious URL Scanner
 - Heuristic Pattern Detection (Punycode, Suspicious Keywords, TLDs, Obfuscation)
 - Unregistered Domain Detection
 - VirusTotal Integration (Malicious / Suspicious Verdicts)
 - Red Flag Summary for each URL
- To enable VirusTotal scanning:
  - Get a free API key from https://www.virustotal.com/gui/join-us
  - Enable "Check with VirusTotal" checkbox in the tool
  - Paste your API key

✅ Example Use Cases:
  - Investigate suspicious domains
  - Identify newly registered or spoofed phishing URLs
  - Analyze free/publicly hosted domains (.tk, .xyz)
  - Run lightweight OSINT checks

📌 Known Limitations:
  - WHOIS data may be unavailable for IPs or some TLDs (e.g. .gov, .edu)
  - VirusTotal API is rate-limited (4 requests/min for free tier)

🔮 Future Improvements:
  - SSL/TLS Certificate Inspection
  - Subdomain Enumeration: Use public sources or APIs to discover subdomains
  - Passive DNS & Historical Records: Track changes in IPs over time (OSINT enhancement)

