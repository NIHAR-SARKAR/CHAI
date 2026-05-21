# Pen Test Tooling: Required CLI & Python Dependencies

To ensure all pen test tools in this project run successfully, make sure **all the following external CLI/system tools** are available in your system's PATH:

## CLI/System Tools Required

- **sqlmap** (`sqlmap`): SQL injection testing.
- **dalfox** (`dalfox`): XSS vulnerability detection.
- **nuclei** (`nuclei`): Vulnerability scanning with community/enterprise templates.
- **nmap** (`nmap`): Port and service discovery.
- **testssl.sh** (`testssl.sh`): SSL/TLS security testing.
- **dig** (`dig`): DNS enumeration.
- **whatweb** (`whatweb`): Web fingerprinting and tech detection.
- **whois** (`whois`): WHOIS lookups.

You must install these tools via your system package manager or by downloading official releases/binaries for your OS.

## Python Dependencies

- **No external/non-stdlib Python packages are directly required by the tools.**
- All required imports are standard library or project-internal modules.
- Ensure you have Python 3.8+ for full standard library support.

---

## Install Example (Ubuntu)

```sh
sudo apt update && sudo apt install -y sqlmap nuclei nmap dnsutils whatweb whois
# dalfox and testssl.sh require manual download (see their official docs):
# Dalfox: https://github.com/hahwul/dalfox
# testssl.sh: https://github.com/drwetter/testssl.sh
```

## Install Example (Windows)

- Download and add to PATH:
  - sqlmap: https://github.com/sqlmapproject/sqlmap
  - dalfox: https://github.com/hahwul/dalfox
  - nuclei: https://github.com/projectdiscovery/nuclei
  - nmap: https://nmap.org/download.html
  - testssl.sh: https://github.com/drwetter/testssl.sh
  - whatweb: https://github.com/urbanadventurer/WhatWeb
  - whois, dig: via third party tools or WSL (Windows Subsystem for Linux)

---

**After installing, verify each tool is available by running:**

```sh
sqlmap --version
dalfox version
nuclei --version
nmap --version
testssl.sh --version
dig -v
whatweb --version
whois --version
```
