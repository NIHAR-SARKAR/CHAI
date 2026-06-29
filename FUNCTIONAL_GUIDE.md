# CHAI — Functional Guide for Beginners

> **Audience:** Someone with zero prior experience with CHAI, penetration testing tools, or MCP servers.
> This document explains WHAT each part does, WHY it exists, and HOW to use it — in plain language.

---

## Table of Contents

1. [What Is CHAI?](#1-what-is-chai)
2. [How CHAI Works — The Big Picture](#2-how-chai-works--the-big-picture)
3. [Setup and First Run](#3-setup-and-first-run)
4. [Configuration Explained](#4-configuration-explained)
5. [The Knowledge Base (KB) — What, Why, How](#5-the-knowledge-base-kb--what-why-how)
6. [How the AI Decision Engine Works](#6-how-the-ai-decision-engine-works)
7. [How LLM Providers Work](#7-how-llm-providers-work)
8. [Security Tools — What Each One Does](#8-security-tools--what-each-one-does)
9. [The Plugin System](#9-the-plugin-system)
10. [Safety, Sandboxing, and Audit](#10-safety-sandboxing-and-audit)
11. [Sessions and Reports](#11-sessions-and-reports)
12. [Step-by-Step: Running Your First Autonomous Scan](#12-step-by-step-running-your-first-autonomous-scan)
13. [Step-by-Step: Using the Knowledge Base](#13-step-by-step-using-the-knowledge-base)
14. [Step-by-Step: Writing a Custom Plugin](#14-step-by-step-writing-a-custom-plugin)
15. [Step-by-Step: Adding a New LLM Provider](#15-step-by-step-adding-a-new-llm-provider)
16. [The Web UI Dashboard](#16-the-web-ui-dashboard)
17. [Windows + WSL Support](#17-windows--wsl-support)
18. [The Fallback & Self-Recovery Engine](#18-the-fallback--self-recovery-engine)
19. [Glossary](#19-glossary)

---

## 1. What Is CHAI?

**CHAI** stands for **Cyber Host Artificial Intelligence**. It is a tool that automatically tests websites and applications for security vulnerabilities — like a robot security tester.

**In simple terms:**

- You give CHAI a website address (like `https://example.com`)
- CHAI connects to an AI (like ChatGPT) to decide what tests to run
- CHAI runs those tests using real hacking tools (nmap, sqlmap, nuclei, etc.)
- CHAI collects all findings and writes a report

**What makes CHAI special:**

- It does NOT need you to manually run each test — it decides on its own what to test next
- It uses AI only at "decision points" (not every single step), which keeps costs low
- Everything runs locally on your machine — no cloud service required (except the AI provider)
- All actions are logged and safety-checked — dangerous commands are blocked automatically

**Important concept — "THIN BRAIN, THICK LOOP":**

- The AI (the "brain") is called only when a decision is needed — like "what should I test next?" or "should I keep going?"
- The "loop" (the actual tool execution) runs locally without AI involvement — it just runs the commands
- This means you spend very little on AI tokens (~9 AI calls for a full test) while getting AI-quality decisions

---

## 2. How CHAI Works — The Big Picture

Think of CHAI as a factory with departments:

```
You (or an MCP Client like Claude Desktop)
    |
    | "Test this website"
    v
+------------------------------------------+
|          CHAI MCP Server                 |
|                                          |
|  1. SESSION MANAGER                     |
|     Creates a "project folder" for this |
|     test run, stores all results         |
|                                          |
|  2. AI PLANNER (the brain)              |
|     Asks the LLM: "What next?"          |
|     Asks the LLM: "Keep going?"         |
|                                          |
|  3. EXECUTION LOOP (the hands)          |
|     Runs actual commands locally        |
|     nmap, sqlmap, nuclei, etc.          |
|                                          |
|  4. KNOWLEDGE BASE (the memory)         |
|     Remembers attack patterns           |
|     Helps AI make better decisions      |
|                                          |
|  5. SAFETY SYSTEM (the guard)           |
|     Blocks dangerous commands           |
|     Runs commands in a sandbox          |
|                                          |
|  6. WSL ADAPTER (the translator)        |
|     On Windows: routes Linux tools      |
|     into WSL automatically              |
|                                          |
|  7. FALLBACK ENGINE (the mechanic)      |
|     When a tool fails: searches web,    |
|     finds fix, applies it, retries      |
+------------------------------------------+
```

### The Flow of an Autonomous Scan

```
Step 1: You start a session (give it a target website)
         |
Step 2: AI PLANNER asks the LLM: "What should I test first?"
         |  LLM answers: "Start with reconnaissance"
         |
Step 3: EXECUTION LOOP runs the recon tool locally (no AI needed here)
         |  Results: "Found 5 open ports, 3 API endpoints"
         |
Step 4: AI PLANNER asks the LLM: "What should I test next?"
         |  LLM answers: "Test SQL injection on the login form"
         |
Step 5: EXECUTION LOOP runs sqlmap locally
         |  Results: "Found SQL injection vulnerability (CRITICAL)"
         |
Step 6: AI PLANNER asks the LLM: "Should I continue?"
         |  LLM answers: "Yes, test for XSS too"
         |
Step 7: ... repeats up to max_phases ...
         |
Step 8: AI PLANNER asks the LLM: "Summarize everything for the report"
         |
Step 9: Report is generated with AI-written executive summary
```

### What is MCP?

MCP stands for **Model Context Protocol**. It is a standard way for AI tools (like Claude Desktop, or any MCP-compatible client) to talk to external tools. CHAI is an **MCP server** — it exposes its functions (tools) through MCP so any MCP client can use them.

**Transport modes:**

- **stdio** — CHAI runs as a subprocess; the client talks to it via standard input/output. Best for local use.
- **streamable-http** — CHAI runs as a web server on port 9010; the client talks to it via HTTP. Best for remote access (e.g., Raspberry Pi on your network).

---

## 3. Setup and First Run

### Prerequisites

| What                        | Why                                | How to check                                          |
| --------------------------- | ---------------------------------- | ----------------------------------------------------- |
| Python 3.11+                | CHAI is a Python application       | `python --version`                                    |
| Kali Linux tools **or** WSL | CHAI runs real security tools      | `nmap --version` (Linux) or `wsl --version` (Windows) |
| An LLM API key              | CHAI needs an AI to make decisions | You need at least one (Azure OpenAI, OpenAI, etc.)    |
| firejail (Linux) or WSL     | Sandboxing for safety              | `firejail --version` (Linux only)                     |

**Platform notes:**

- **Linux / Raspberry Pi / Kali** — Native support. All tools run directly.
- **Windows** — Requires **WSL** (Windows Subsystem for Linux). CHAI routes all Linux commands into WSL automatically. See [Section 17: Windows + WSL Support](#17-windows--wsl-support) for details.
- **macOS** — Partial support. Some tools may need Homebrew installation.

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/NIHAR-SARKAR/CHAI.git
cd CHAI

# 2. Create a Python virtual environment
python -m venv .venv

# Linux/Mac:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# 3. Install Python dependencies
pip install -r backend/requirements.txt

# 4. Set up your API keys
cp backend/.security.yml.example backend/.security.yml
# Now edit backend/.security.yml and add your API key(s)
# Example: add your Azure OpenAI key under the azure_openai section

# 5. Create required directories
# Linux:
sudo mkdir -p /opt/sessions /opt/logs /opt/kb
# Windows PowerShell:
New-Item -ItemType Directory -Force -Path "C:\opt\sessions"
New-Item -ItemType Directory -Force -Path "C:\opt\logs"
New-Item -ItemType Directory -Force -Path "C:\opt\kb"

# 6. Start the server (MCP + Web UI)
cd backend
python main.py --transport streamable-http
```

### Verifying It Works

After starting the server, you should see output like:

```
CHAI MCP Server v2.0.0 starting on port 9010
Starting CHAI Web UI on port 8060
```

You can then:

- Open the **Web UI** at `http://localhost:8060`
- Connect from any **MCP client** (Claude Desktop, etc.) on port 9010

---

## 4. Configuration Explained

CHAI uses **two configuration files**:

### `backend/config.yaml` — Main Settings (Safe to commit to git)

| Section      | What It Controls                   | Key Settings                                                                                 |
| ------------ | ---------------------------------- | -------------------------------------------------------------------------------------------- |
| `server`     | How CHAI runs as a server          | `transport` (stdio or streamable-http), `sse_port` (default 9010), `web_port` (default 8060) |
| `paths`      | Where files are stored             | `kb_path`, `session_db`, `reports_path`, `audit_log_path`                                    |
| `sandbox`    | Resource limits for tool execution | `max_ram_mb` (384), `max_cpu_percent` (50), `command_timeout` (300s)                         |
| `llm`        | Which AI provider to use           | `active_provider`, `fallback_provider`, `max_tokens`, `temperature`                          |
| `ai_planner` | How the AI planner behaves         | `max_phases` (4), `stop_on_critical` (true), `use_graph_prefilter` (true)                    |
| `plugins`    | Which plugins are enabled          | `bundled.feroxbuster`, `bundled.metasploit`, `bundled.burp_api`                              |

**Key settings explained:**

- **`llm.active_provider`**: Which AI service to use. Options: `azure_openai`, `openai`, `anthropic`, `amazon_bedrock`, `openrouter`, `huggingface`
- **`llm.fallback_provider`**: If the active provider fails, try this one instead
- **`ai_planner.max_phases`**: Maximum number of test phases in an autonomous scan (default 4)
- **`ai_planner.stop_on_critical`**: If `true`, stop the scan immediately when a critical vulnerability is found
- **`ai_planner.use_graph_prefilter`**: If `true`, use the Knowledge Base graph to narrow down candidate tests before asking the AI (saves tokens and improves decisions)

### `backend/.security.yml` — Secrets (NEVER commit to git)

This file holds your API keys. Structure:

```yaml
azure_openai:
  api_key: "your-key-here"

openai:
  api_key: "your-key-here"

anthropic:
  api_key: "your-key-here"

openrouter:
  api_key: "your-key-here"

huggingface:
  api_key: "your-key-here"

amazon_bedrock:
  access_key_id: ""
  secret_access_key: ""

burp_api:
  api_key: ""
```

You only need to fill in the provider(s) you plan to use.

---

## 5. The Knowledge Base (KB) — What, Why, How

### What is the KB?

The Knowledge Base is CHAI's **memory of attack patterns**. It knows:

- **50+ attack techniques** — like "SQL Injection", "XSS Reflected", "JWT None Algorithm", etc.
- **Attack chains** — sequences like "Recon → Find Login → Test SQLi → Exploit"
- **Playbooks** — pre-defined test plans for different types of targets (web apps, APIs, networks, etc.)
- **Searchable documents** — any text you index for semantic search

### Why does the KB exist?

Without the KB, the AI planner has to decide what to test next based only on the current findings. With the KB, the AI gets **pre-filtered suggestions** based on:

- What attack type was just found
- What attacks logically follow from that finding
- What the target type is (web app, API, etc.)

This makes the AI's decisions **better and cheaper** — instead of the LLM choosing from 17 possible tools, it gets 3-4 relevant suggestions from the KB graph.

### The Three KB Components

#### 5.1. Graph Database (`kb/graph_db.py`)

**What it is:** An SQLite database that stores attack techniques as a **directed graph** (nodes + edges).

**Nodes (techniques):** Each technique has:
| Field | Meaning | Example |
|-------|---------|---------|
| `id` | Unique identifier | `sqli_error` |
| `name` | Human-readable name | `SQL Injection - Error Based` |
| `category` | Type of attack | `injection` |
| `description` | What this technique does | `Tests for SQL error messages...` |
| `prerequisites` | What must be true first | `Requires input fields` |
| `indicators` | How to recognize success | `SQL error in response` |
| `mitre_tactic` | MITRE ATT&CK tactic | `TA0006 - Credential Access` |
| `tier` | Risk level of this technique | `tier1`, `tier2`, or `tier3` |
| `tags` | Searchable labels | `["web", "injection", "database"]` |

**Edges (attack chains):** Connect techniques with:
| Field | Meaning | Example |
|-------|---------|---------|
| `from_technique` | Source technique | `recon_active` |
| `to_technique` | Next logical step | `sqli_error` |
| `condition` | When to follow this path | `Input fields discovered` |
| `probability` | How likely this path is useful (0-1) | `0.85` |

**How the graph is queried:**
When the AI planner needs suggestions, it calls `get_attack_chain(entry_attack, goal, max_depth)`. This uses a **recursive SQL query** (CTE) to walk the graph from the current technique, following edges, and returns possible next steps sorted by probability.

**Example chain:**

```
recon_active → (found input fields) → sqli_error → (found SQL error) → sqli_blind
```

**5 pre-seeded playbooks** are stored in the graph:
| Playbook | When to Use | Phases |
|----------|------------|--------|
| `web_app_basic` | Standard web application | recon → scan → injection → auth → xss → misconfig → report |
| `api_security` | API-focused targets | recon → scan → injection → auth → api → rate_limit → report |
| `network_infra` | Network infrastructure | recon → scan → network → ssl → report |
| `red_team` | Full red team engagement | recon → scan → injection → auth → exploit → post_exploit → report |
| `mobile_app` | Mobile application backends | recon → scan → api → auth → sensitive_data → report |

#### 5.2. Playbook Loader (`kb/playbook_loader.py`)

**What it is:** A system for loading **playbooks from markdown files**.

**What a playbook markdown file looks like:**

```markdown
# My Custom Web App Test Plan

## Reconnaissance

Use `run_recon` with recon_type="active" to discover the attack surface.

## Scanning

Run `scan_vulnerabilities` with scanner="nuclei" to find known vulnerabilities.

## Exploitation

If SQL injection found, use `test_injection` with injection_type="sqli".
If XSS found, use `test_xss` with xss_type="reflected".

## Reporting

Generate report with `generate_report` format="markdown".
```

**How it works:**

1. The loader reads a markdown file
2. It splits the content into **sections** by finding headings (`#`, `##`, etc.)
3. Each section is categorized (recon, scan, exploit, post_exploit, report)
4. It extracts **tool references** — mentions of tools like `run_recon`, `test_injection`, etc.
5. It extracts **metadata** from YAML frontmatter or the first heading

**How to use it:**

```python
from kb.playbook_loader import PlaybookLoader

loader = PlaybookLoader()
loader.load_playbook("path/to/my_playbook.md")

# List all loaded playbooks
playbooks = loader.list_playbooks()

# Get a specific playbook
playbook = loader.get_playbook("my_playbook")
# Returns: {name, metadata, sections: {recon: "...", scan: "...", ...}, tools: [...]}
```

#### 5.3. Vector Search (`kb/vector_search.py`)

**What it is:** A search engine for the KB. You can index any text document and then search it using **natural language queries**.

**Two search modes:**

| Mode                    | How It Works                                                                                        | When It's Used                                              |
| ----------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| **Vector search**       | Converts text to numbers (embeddings) using AI, then finds similar content by mathematical distance | When `sentence-transformers` and `sqlite-vec` are installed |
| **BM25 keyword search** | Classic keyword matching with relevance scoring (like a search engine)                              | Fallback when vector dependencies are missing               |

**How to use it:**

```python
from kb.vector_search import VectorSearch

vs = VectorSearch(db_path="/opt/kb/search.db")

# Index documents
vs.index_document("sqli_guide", "SQL injection attacks exploit database queries...", {"category": "injection"})
vs.index_document("xss_guide", "Cross-site scripting injects JavaScript...", {"category": "xss"})

# Search using natural language
results = vs.search("how to test for database attacks", top_k=3)
# Returns: [{"doc_id": "sqli_guide", "score": 0.87, "content": "...", "metadata": {...}}, ...]

# Search works even with fuzzy/imprecise queries
results = vs.search("injecting code into websites", top_k=3)
# Will likely return the XSS guide too, because the meaning is similar
```

### How the KB Connects to the AI Planner

```
AI Planner needs to decide "what to test next"
    |
    v
Is use_graph_prefilter = true in config?
    |
    YES → Query Graph DB: "What techniques follow from what we just found?"
    |      Returns 3-5 candidate techniques with high probability
    |
    v
Send candidates + current findings to LLM
    |
    v
LLM picks one: {next_tool: "test_injection", args: {injection_type: "sqli"}, ...}
```

Without the KB prefilter, the LLM would receive all 17 tools as options, which is more expensive and produces worse decisions.

### How to Utilize the KB Effectively

#### Add Custom Attack Techniques

```python
from kb.graph_db import GraphDB

graph = GraphDB(db_path="/opt/kb/graph.db")

# Add a new technique
graph.add_technique(
    technique_id="custom_api_fuzz",
    name="Custom API Fuzzing",
    category="api",
    description="Fuzz API endpoints for unexpected behaviors",
    prerequisites="API endpoints discovered",
    indicators="Unexpected response codes or data",
    mitre_tactic="TA0005",
    mitre_technique="T1190",
    tier="tier2",
    tags=["api", "fuzzing", "custom"]
)

# Add a chain from recon to your new technique
graph.add_attack_chain(
    from_technique="recon_active",
    to_technique="custom_api_fuzz",
    condition="API endpoints found during recon",
    probability=0.7
)
```

#### Add Custom Playbook Files

1. Create a markdown file in the KB directory:

```markdown
---
author: your-name
target_type: custom_app
---

# Custom Application Security Test

## Reconnaissance

Run `run_recon` with target and recon_type="active".

## Scanning

Run `scan_vulnerabilities` with scanner="nuclei".

## Exploitation

Run `test_injection` and `test_xss` based on findings.
```

2. Load it in your code or via the MCP tool interface.

#### Index Reference Documents

```python
from kb.vector_search import VectorSearch

vs = VectorSearch(db_path="/opt/kb/search.db")

# Index OWASP references, custom notes, CVE descriptions, etc.
vs.index_document("owasp_top10_2021", "A01:2021-Broken Access Control...", {"source": "owasp"})
vs.index_document("custom_note_1", "Our app uses JWT for auth, check for none-algorithm...", {"source": "internal"})

# Later, search for context
results = vs.search("authentication vulnerabilities in JWT", top_k=5)
```

---

## 6. How the AI Decision Engine Works

The AI planner (`core/ai_planner.py`) makes exactly **3 types of decisions**, each using a different prompt:

### Decision 1: PLAN — "What should I test next?"

**When:** At the start of each phase
**Input to LLM:** Compact digest of current findings (<500 tokens)
**What the LLM returns:**

```json
{
  "next_tool": "test_injection",
  "args": { "injection_type": "sqli" },
  "rationale": "Active recon found login form with input fields, high probability of SQLi",
  "expected_finding_type": "injection",
  "confidence": 0.85
}
```

**How the KB helps:** If `use_graph_prefilter` is true, the planner first queries the graph DB for candidate next techniques based on current findings, then sends only those candidates to the LLM instead of all 17 tools.

### Decision 2: EVALUATE — "Should I continue testing?"

**When:** After each phase completes
**Input to LLM:** Summary of findings (top 10, critical/high counts)
**What the LLM returns:**

```json
{
  "continue": true,
  "reason": "Multiple high-severity injection findings, should test for XSS and auth bypass",
  "priority_findings": ["SQL injection on login", "No CORS policy"],
  "risk_score": 7.5
}
```

**Hard stop:** If `stop_on_critical` is true and any finding has CVSS >= 9.0, the scan stops immediately WITHOUT asking the LLM.

### Decision 3: SUMMARIZE — "Write the report summary"

**When:** After all phases complete (if `generate_report=true`)
**Input to LLM:** Full findings digest
**What the LLM returns:**

```json
{
  "executive_summary": "The target application has 3 critical vulnerabilities...",
  "risk_narrative": "The SQL injection vulnerability allows an attacker to...",
  "remediation_priorities": [
    "1. Fix SQL injection on login endpoint",
    "2. Implement CORS policy"
  ]
}
```

### Token Budget

For a typical 4-phase scan:

- Plan x 4 = 4 LLM calls
- Evaluate x 4 = 4 LLM calls
- Summarize x 1 = 1 LLM call
- **Total: ~9 LLM calls** (very efficient compared to calling the LLM for every tool step)

---

## 7. How LLM Providers Work

CHAI supports 6 AI providers. All share the same interface:

```
You choose provider in config.yaml
    |
    v
provider_factory.py creates the right provider
    |
    v
If primary provider fails → fallback provider is tried
    |
    v
Provider sends prompt to the AI → gets JSON response
```

### Provider Comparison

| Provider             | What You Need                                  | Cost                | Best For                                   |
| -------------------- | ---------------------------------------------- | ------------------- | ------------------------------------------ |
| **Azure OpenAI**     | Azure subscription + API key + deployment name | Medium-High         | Enterprise use, multiple model deployments |
| **OpenAI (Direct)**  | OpenAI API key                                 | Medium-High         | Quick setup, GPT-4 access                  |
| **Anthropic Claude** | Anthropic API key                              | Medium              | High-quality reasoning                     |
| **Amazon Bedrock**   | AWS account + IAM credentials                  | Variable            | AWS-heavy environments                     |
| **OpenRouter**       | OpenRouter API key                             | Low                 | Access 100+ models cheaply                 |
| **HuggingFace**      | HuggingFace API token                          | Free tier available | Experimentation, open-source models        |

### How to Switch Providers

1. Add your API key to `backend/.security.yml`
2. Change `llm.active_provider` in `backend/config.yaml`
3. Optionally set `llm.fallback_provider` as backup
4. Restart the server

**Example — Switch from Azure OpenAI to OpenRouter:**

```yaml
# backend/config.yaml
llm:
  active_provider: "openrouter"
  fallback_provider: "azure_openai"
  openrouter:
    enabled: true
    model: "openai/gpt-4o"
    api_base: "https://openrouter.ai/api/v1"
```

```yaml
# backend/.security.yml
openrouter:
  api_key: "sk-or-v1-your-key"
```

---

## 8. Security Tools — What Each One Does

CHAI has 17 security tools. Each one runs real command-line tools and returns structured findings.

### Understanding Tool Tiers

| Tier       | Meaning                | Examples                   | Risk                      |
| ---------- | ---------------------- | -------------------------- | ------------------------- |
| **Tier 1** | Passive/low-impact     | WHOIS, DNS, header checks  | Safe — only observes      |
| **Tier 2** | Active but standard    | nmap, nuclei, sqlmap       | Moderate — sends probes   |
| **Tier 3** | Exploitation/dangerous | Metasploit, reverse shells | High — could cause damage |

Higher-tier tools require more safety checks and may be blocked by the safety policy depending on configuration.

### Tool-by-Tool Explanation

#### Reconnaissance (`tools/recon.py`)

**Purpose:** Discover what the target looks like before attacking.

| Sub-tool  | What It Does                                                              | Real Tools Used                               |
| --------- | ------------------------------------------------------------------------- | --------------------------------------------- |
| `passive` | Looks up WHOIS info and DNS records — no contact with the target          | `whois`, `dig`                                |
| `active`  | Actively probes the target to find technologies, APIs, ports, directories | `whatweb`, `ffuf`, `curl`, `nmap`, `gobuster` |

**What it finds:**

- What software the server runs (Apache, Nginx, etc.)
- What API endpoints exist
- What ports are open
- What directories are accessible
- Whether Swagger/API docs are exposed

**When to use:** Always first — every scan starts with recon.

---

#### Vulnerability Scanning (`tools/scan.py`)

**Purpose:** Automatically scan for known vulnerabilities.

| Scanner  | What It Does                                         | Real Tool Used |
| -------- | ---------------------------------------------------- | -------------- |
| `nuclei` | Scans against 1000s of known vulnerability templates | `nuclei`       |
| `nmap`   | Scans specific ports for service versions            | `nmap -sV`     |

**When to use:** After recon, before manual testing.

---

#### Injection Testing (`tools/injection.py`)

**Purpose:** Test if the target is vulnerable to code injection attacks.

| Type                | What It Tests                                                          | Real Tool Used   |
| ------------------- | ---------------------------------------------------------------------- | ---------------- |
| `sqli`              | SQL Injection — can an attacker manipulate database queries?           | `sqlmap`, `curl` |
| `nosqli`            | NoSQL Injection — same for MongoDB/NoSQL databases                     | `curl`           |
| `command_injection` | OS Command Injection — can an attacker run system commands?            | `curl`           |
| `ssti`              | Server-Side Template Injection — can an attacker inject template code? | `curl`           |
| `xxe`               | XML External Entity — can an attacker read server files via XML?       | `curl`           |

**When to use:** When recon found input forms, APIs, or XML endpoints.

---

#### Authentication Testing (`tools/auth.py`)

**Purpose:** Test if the target's login/authentication system has flaws.

| Type                   | What It Tests                                                      |
| ---------------------- | ------------------------------------------------------------------ |
| `bypass`               | Can you access admin pages without logging in?                     |
| `jwt`                  | Are JWT tokens secure? (none-algorithm attack)                     |
| `brute_force`          | Can you guess passwords by trying many?                            |
| `password_reset`       | Is the password reset mechanism predictable?                       |
| `session_fixation`     | Are session cookies properly secured? (HttpOnly, Secure, SameSite) |
| `privilege_escalation` | Can a normal user access admin functions?                          |

**When to use:** When the target has a login system.

---

#### Network Testing (`tools/network.py`)

**Purpose:** Test the network-level security of the target.

| Type        | What It Tests                                                    | Real Tool Used |
| ----------- | ---------------------------------------------------------------- | -------------- |
| `ssl`       | SSL/TLS configuration and known vulnerabilities                  | `testssl.sh`   |
| `headers`   | Are security headers present? (HSTS, CSP, X-Frame-Options, etc.) | `curl`         |
| `port_scan` | What ports/services are running?                                 | `nmap`         |

---

#### XSS Testing (`tools/xss.py`)

**Purpose:** Test for Cross-Site Scripting — can an attacker inject JavaScript?

| Type        | What It Tests                                               | Real Tool Used |
| ----------- | ----------------------------------------------------------- | -------------- |
| `reflected` | Is user input reflected back in the page without filtering? | `curl`         |
| `stored`    | Can XSS payloads be stored and shown to other users?        | `curl`         |
| `dom`       | Is the page's JavaScript processing user input unsafely?    | `dalfox`       |
| `header`    | Can XSS work via HTTP headers (Referer, User-Agent)?        | `curl`         |
| `csp_check` | Is Content Security Policy properly configured?             | `curl`         |

---

#### SSRF Testing (`tools/ssrf.py`)

**Purpose:** Test for Server-Side Request Forgery — can the server be tricked into making requests to internal resources?

Tests 5 payloads targeting:

- AWS metadata endpoint (169.254.169.254)
- Localhost services (SSH on port 22, Redis on port 6379)
- Internal services
- File protocol (file:///etc/passwd)

---

#### Access Control Testing (`tools/access_control.py`)

**Purpose:** Test if access controls are properly enforced.

| Type               | What It Tests                                                                        |
| ------------------ | ------------------------------------------------------------------------------------ |
| `idor`             | Insecure Direct Object Reference — can you access other users' data by changing IDs? |
| `bola`             | Broken Object Level Authorization — same as IDOR but for API objects                 |
| `path_traversal`   | Can you access files outside the intended directory? (`../../etc/passwd`)            |
| `method_tampering` | Can you bypass restrictions by using different HTTP methods? (PUT instead of GET)    |
| `forced_browsing`  | Can you access admin/internal pages without authentication?                          |

---

#### API Security Testing (`tools/api_security.py`)

**Purpose:** Test API-specific vulnerabilities.

| Type                    | What It Tests                                                     |
| ----------------------- | ----------------------------------------------------------------- |
| `mass_assignment`       | Can you set fields you shouldn't? (role=admin, isAdmin=true)      |
| `api_versioning`        | Are old, vulnerable API versions still accessible? (v0, v1, beta) |
| `graphql_introspection` | Is GraphQL schema exposed to anyone?                              |

---

#### Misconfiguration Testing (`tools/misconfig.py`)

**Purpose:** Test for common security misconfigurations.

| Type               | What It Tests                                                        |
| ------------------ | -------------------------------------------------------------------- |
| `cors`             | Is Cross-Origin Resource Sharing too permissive? (evil.com allowed?) |
| `verbose_errors`   | Do error messages reveal too much? (stack traces, SQL queries)       |
| `debug_endpoints`  | Are debug/admin endpoints publicly accessible? (/debug, /actuator)   |
| `security_headers` | Are recommended security headers present?                            |

---

#### Rate Limit Testing (`tools/rate_limit.py`)

**Purpose:** Test if the target limits how many requests you can make.

| Type               | What It Tests                                                        |
| ------------------ | -------------------------------------------------------------------- |
| `login_rate_limit` | Can you try 50 wrong passwords without being blocked?                |
| `api_rate_limit`   | Can you make 100 API calls rapidly without being throttled?          |
| `bypass_headers`   | Can you bypass rate limits by spoofing IP headers? (X-Forwarded-For) |

---

#### Sensitive Data Testing (`tools/sensitive_data.py`)

**Purpose:** Test if sensitive data is accidentally exposed.

| Type               | What It Tests                                                      |
| ------------------ | ------------------------------------------------------------------ |
| `js_secrets`       | Are API keys, passwords, or tokens embedded in JavaScript files?   |
| `api_overexposure` | Does the API return sensitive fields (password, SSN, credit card)? |
| `http_https`       | Does the site force HTTPS? Is HSTS enabled?                        |
| `git_backup`       | Are sensitive files accessible? (.git/config, .env, backup.sql)    |

---

#### Business Logic Testing (`tools/business_logic.py`)

**Purpose:** Test for flaws in the application's business rules.

| Type              | What It Tests                                             |
| ----------------- | --------------------------------------------------------- |
| `negative_values` | Can you order items with negative quantity or zero price? |
| `coupon_abuse`    | Can you use a single-use coupon multiple times?           |

---

#### PoC Generation (`tools/poc.py`)

**Purpose:** Generate a Proof of Concept document for a vulnerability — step-by-step instructions showing how the vulnerability was found and how to exploit it.

---

#### Custom Command Execution (`tools/exec.py`)

**Purpose:** Run any command you want (subject to safety checks).

**Example:** `execute_command(command="nmap -sV -p 80,443 target.com")`

---

#### Findings Analysis (`tools/analyze.py`)

**Purpose:** Summarize and categorize all findings so far.

Produces a **compact digest** (under 500 tokens) for the AI planner, containing:

- Target and scope
- What's been tested already
- Confirmed vulnerabilities with severity
- Total findings count

---

#### Report Generation (`tools/report.py`)

**Purpose:** Generate a professional penetration test report.

**Formats:**

- **Markdown**: Full report with executive summary, risk narrative, remediation priorities, findings grouped by severity
- **JSON**: Structured data for programmatic consumption

The report can include an **AI narrative** — an LLM-written executive summary if `include_ai_narrative` is true in config.

---

#### Autonomous Scan Orchestrator (`tools/autonomous.py`)

**Purpose:** The top-level tool that runs the entire autonomous scan flow (plan → execute → evaluate → repeat → report).

This is the tool you call when you want CHAI to do everything automatically.

---

## 9. The Plugin System

### What Are Plugins?

Plugins are **optional add-on tools** that extend CHAI's capabilities. They follow a standard format so they can be loaded automatically without changing CHAI's core code.

### Bundled Plugins (come with CHAI)

| Plugin             | What It Does                                          | Enabled by Default? | Tier  |
| ------------------ | ----------------------------------------------------- | ------------------- | ----- |
| **Feroxbuster**    | Fast directory bruteforcing (alternative to gobuster) | Yes                 | tier2 |
| **Metasploit**     | Run Metasploit exploits and modules                   | No                  | tier3 |
| **Burp Suite API** | Connect to Burp Suite Pro for scan results            | No                  | tier2 |

### How Plugins Auto-Load

When CHAI starts:

1. It scans `plugins/bundled/` for Python files
2. It scans the external plugins directory (from config)
3. For each file, it checks:
   - Does it contain a `PentestPlugin` subclass?
   - Is it enabled in config? (for bundled plugins)
   - Is the required binary installed? (e.g., `msfconsole` for Metasploit)
4. If all checks pass → the plugin is loaded and available

### How to Use Plugins

```python
# List available plugins
list_plugins()
# Returns: [{"name": "feroxbuster", "display_name": "Feroxbuster", "tier": "tier2", ...}]

# Run a plugin
run_plugin(session_id="sess-abc-123", plugin_name="feroxbuster", target="https://target.com")
```

### How to Write a Custom Plugin

See [Section 14: Step-by-Step Writing a Custom Plugin](#14-step-by-step-writing-a-custom-plugin).

---

## 10. Safety, Sandboxing, and Audit

### Why Safety Matters

CHAI runs real hacking tools. Without safeguards, it could:

- Accidentally damage the target system
- Run dangerous commands (like `rm -rf /`)
- Execute commands outside the defined scope

### Three Layers of Protection

#### Layer 1: Safety Policy (`core/safety_policy.py`)

**What it does:** Validates every command before execution.

| Check                    | What It Blocks                                                                    |
| ------------------------ | --------------------------------------------------------------------------------- | --- | ---------------------------------------------- |
| **Global denylist**      | 36 dangerous patterns: `rm -rf /`, fork bombs, `curl \| sh`, reverse shells, etc. |
| **Tier check**           | Ensures tier3 tools only run when explicitly allowed                              |
| **Scope check**          | Ensures commands only target the defined scope (domain/IP matching)               |
| **Rate limit**           | Prevents too many commands per session per tier (60s window)                      |
| **Command sanitization** | Removes shell chaining (`; &&                                                     |     | `), validates pipes, blocks injection patterns |

**If a command is blocked:** The command is NOT executed, the reason is logged, and a "blocked" result is returned.

#### Layer 2: Process Controller (`core/process_controller.py`)

**What it does:** Runs commands in a restricted environment (sandbox).

| Sandbox Level | How It Works                                                                                                            | When Used                      |
| ------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `none`        | Raw command, no restrictions                                                                                            | Default on Windows             |
| `firejail`    | Wraps command in firejail with: restricted filesystem, no network access beyond target, memory/CPU limits, private /tmp | Default on Linux (recommended) |
| `cgroups`     | Uses Linux cgroups for memory and CPU limits                                                                            | Alternative to firejail        |
| `chroot`      | Runs in an isolated filesystem root                                                                                     | For maximum isolation          |

All commands have a **timeout** (default 300s). If a command runs too long, it is killed (SIGTERM → wait 5s → SIGKILL).

#### Layer 3: Audit Logger (`core/audit_logger.py`)

**What it does:** Records every command and its result in an **immutable** log file.

- **Redaction**: API keys, passwords, tokens, and secrets are automatically replaced with `[REDACTED]`
- **Append-only**: Log entries are appended, never modified or deleted
- **What's logged**: Session ID, command, result (stdout/stderr/return code), duration, timestamp

---

## 11. Sessions and Reports

### What Is a Session?

A session is a **single penetration test engagement** — like a project folder for one target.

**Session lifecycle:**

```
initialized → running → complete
                      → stopped (manually stopped)
                      → error (something went wrong)
```

**What a session stores:**

- Target URL
- Test type (web_app, api, network, etc.)
- Scope (allowed domains/IPs)
- All findings discovered
- All AI decisions made
- Currently running processes (for emergency stop)

### What Is a Finding?

Every vulnerability discovered is recorded as a **Finding** with:

| Field         | Meaning                           | Example                                             |
| ------------- | --------------------------------- | --------------------------------------------------- |
| `attack_type` | Category of vulnerability         | `sqli`                                              |
| `confidence`  | How sure we are (0-1)             | `0.9`                                               |
| `endpoint`    | Where the vulnerability was found | `/api/login`                                        |
| `evidence`    | Proof that it exists              | `"SQL error: You have an error in your SQL syntax"` |
| `cvss_score`  | Severity score (0-10)             | `9.8`                                               |
| `severity`    | Human-readable level              | `critical`, `high`, `medium`, `low`, `info`         |
| `remediation` | How to fix it                     | `"Use parameterized queries"`                       |

### Severity Levels

| Severity     | CVSS Range | Meaning                                             |
| ------------ | ---------- | --------------------------------------------------- |
| **Critical** | 9.0 - 10.0 | Immediate threat — system can be fully compromised  |
| **High**     | 7.0 - 8.9  | Serious — significant data or functionality at risk |
| **Medium**   | 4.0 - 6.9  | Moderate — limited impact but should be fixed       |
| **Low**      | 0.1 - 3.9  | Minor — informational, low exploitation likelihood  |
| **Info**     | 0          | No vulnerability — informational note               |

### Reports

Generated reports contain:

1. **Executive Summary** — High-level overview (optionally AI-written)
2. **Risk Narrative** — Description of overall risk posture (optionally AI-written)
3. **Remediation Priorities** — Ordered list of what to fix first (optionally AI-written)
4. **Findings by Severity** — All findings grouped as Critical → High → Medium → Low → Info
5. **Detailed Findings** — Each finding with endpoint, evidence, CVSS score, and remediation

---

## 12. Step-by-Step: Running Your First Autonomous Scan

### Prerequisites Checklist

- [ ] CHAI server is running (`cd backend && python main.py --transport streamable-http`)
- [ ] At least one LLM provider is configured (API key in `backend/.security.yml`)
- [ ] Target is in scope and you have authorization to test it
- [ ] Required pentest tools are installed (nmap, nuclei, etc.)

### Step 1: Initialize a Session

```python
initialize_session(
    target="https://your-target.com",
    test_type="web_app",        # Options: web_app, api, network, red_team, mobile_app
    scope=["your-target.com"]   # Domains/IPs you're allowed to test
)
```

This creates a session and returns a `session_id`.

### Step 2: Run the Autonomous Scan

```python
run_autonomous_scan(
    session_id="sess-abc-123",
    max_phases=4,              # How many test phases to run
    stop_on_critical=True,     # Stop immediately if a critical vuln is found
    generate_report=True       # Generate a report when done
)
```

### Step 3: Wait

The scan will run autonomously. Depending on the target and number of phases, this can take 15-30 minutes.

The AI will:

1. Plan what to test first (e.g., reconnaissance)
2. Execute the recon tool locally
3. Evaluate the findings
4. Plan the next test (e.g., SQL injection)
5. Execute the injection tool
6. ... and so on

### Step 4: Review the Report

The report is saved to the path returned in the response (e.g., `/opt/sessions/reports/sess-abc-123.md`).

### Manual Alternative

If you want more control, call tools individually instead of running autonomously:

```python
# 1. Start a session
initialize_session(target="https://target.com", test_type="web_app", scope=["target.com"])

# 2. Run recon
run_recon(session_id="sess-abc-123", target="https://target.com", recon_type="active")

# 3. Check findings
get_session_status(session_id="sess-abc-123")

# 4. Run specific tests
scan_vulnerabilities(session_id="sess-abc-123", target="https://target.com", scanner="nuclei")
test_injection(session_id="sess-abc-123", target="https://target.com", injection_type="sqli")
test_authentication(session_id="sess-abc-123", target="https://target.com", test_type="bypass")

# 5. Generate report
generate_report(session_id="sess-abc-123", format="markdown")
```

### Emergency Stop

If something goes wrong:

```python
emergency_stop(session_id="sess-abc-123")
```

This kills all running processes for that session immediately.

---

## 13. Step-by-Step: Using the Knowledge Base

### Scenario 1: Understanding Pre-built Attack Patterns

The KB comes with 50+ pre-seeded attack techniques and 33 attack chains. To explore them:

```python
# Search for techniques by category
graph.search_techniques(category="injection")
# Returns: [technique objects for sqli_error, sqli_blind, nosqli, command_injection, ...]

# Search by tier (safety level)
graph.search_techniques(tier="tier1")
# Returns: [safe, passive techniques only]

# Search by tag
graph.search_techniques(tags=["web", "database"])
# Returns: [techniques tagged with both "web" AND "database"]
```

### Scenario 2: Getting Next-Step Suggestions

```python
# After finding SQL injection, what should we test next?
graph.get_attack_chain(entry_attack="sqli_error", max_depth=2)
# Returns: [
#   {technique: "sqli_blind", probability: 0.9, depth: 1, condition: "Error-based SQLi confirmed"},
#   {technique: "data_exfiltration", probability: 0.8, depth: 2, condition: "SQLi exploited"},
#   ...
# ]
```

### Scenario 3: Loading a Playbook

```python
# Get a pre-built playbook from the graph DB
graph.get_playbook("web_app_basic")
# Returns: {id: "web_app_basic", name: "Basic Web Application", phases: ["recon", "scan", "injection", "auth", "xss", "misconfig", "report"]}

# Or load a custom markdown playbook
from kb.playbook_loader import PlaybookLoader
loader = PlaybookLoader()
loader.load_playbook("/opt/kb/my_custom_playbook.md")
loader.list_playbooks()
```

### Scenario 4: Indexing and Searching Documents

```python
from kb.vector_search import VectorSearch
vs = VectorSearch(db_path="/opt/kb/search.db")

# Index some reference documents
vs.index_document("cve-2024-1234", "Apache Struts RCE via OGNL injection...", {"type": "cve", "severity": "critical"})
vs.index_document("owasp-a01", "Broken Access Control allows users to act outside...", {"type": "owasp"})

# Search with natural language
results = vs.search("remote code execution in web frameworks", top_k=5)
for r in results:
    print(f"  {r['doc_id']}: score={r['score']:.2f}")
    print(f"  Content: {r['content'][:100]}...")
```

### Scenario 5: Adding Your Own Techniques to the Graph

```python
graph.add_technique(
    technique_id="grpc_template_injection",
    name="gRPC Template Injection",
    category="injection",
    description="Tests for template injection in gRPC message fields",
    prerequisites="gRPC service discovered",
    indicators="Template expression evaluated in response",
    mitre_tactic="TA0006",
    mitre_technique="T1190",
    tier="tier2",
    tags=["grpc", "injection", "template"]
)

# Link it into the attack chain
graph.add_attack_chain(
    from_technique="recon_active",
    to_technique="grpc_template_injection",
    condition="gRPC service detected during recon",
    probability=0.5
)
```

---

## 14. Step-by-Step: Writing a Custom Plugin

### Step 1: Create the Plugin File

Create a file like `plugins/external/my_plugin.py`:

```python
from plugins.plugin_base import PentestPlugin, PluginMetadata, PluginResult
from models.session import Finding

class MyPlugin(PentestPlugin):
    @property
    def metadata(self):
        return PluginMetadata(
            name="my_tool",                    # Unique identifier
            display_name="My Custom Tool",     # Human-readable name
            version="1.0.0",                   # Version
            description="Does something cool",  # What it does
            tier="tier2",                      # Safety tier (tier1/2/3)
            requires_binary="my_tool",         # CLI binary name (checked with `which`)
            requires_network=True,             # Needs network access?
            tags=["custom", "recon"]           # Searchable tags
        )

    async def run(self, session_id, target, args, process_controller, safety_policy, session_manager):
        # 1. Build your command
        command = f"my_tool --json {target}"

        # 2. VALIDATE through safety policy (MANDATORY)
        validation = await safety_policy.validate(command, session_id, target)
        if not validation["approved"]:
            return PluginResult(success=False, error=f"Blocked: {validation['reason']}")

        # 3. EXECUTE through process controller (MANDATORY — never use subprocess directly)
        result = await process_controller.run(
            validation["modified_command"],
            session_id=session_id,
            timeout=120
        )

        # 4. Parse results and create findings
        findings = []
        if "vulnerability" in result["stdout"]:
            findings.append(Finding(
                attack_type="custom",
                confidence=0.8,
                endpoint=target,
                evidence=result["stdout"][:500],
                cvss_score=7.5,
                severity="high",
                remediation="Fix the issue"
            ))

        return PluginResult(
            success=True,
            findings=findings,
            raw_output=result["stdout"],
            duration_ms=result["duration_ms"]
        )

    async def is_available(self):
        # Return True if the required binary is installed
        import shutil
        return shutil.which(self.metadata.requires_binary) is not None
```

### Step 2: Restart the Server

The plugin auto-discovers on startup. No code changes needed.

### Step 3: Use the Plugin

```python
run_plugin(session_id="sess-abc-123", plugin_name="my_tool", target="https://target.com")
```

### Critical Rules for Plugins

1. **ALWAYS validate commands** through `safety_policy.validate()` before execution
2. **ALWAYS execute** through `process_controller.run()` — never use `subprocess` directly
3. **Never hardcode** secrets or credentials in plugin code
4. **Return structured findings** using the `Finding` model for consistency

---

## 15. Step-by-Step: Adding a New LLM Provider

### Step 1: Create the Provider File

Create `llm/providers/my_provider.py`:

```python
from llm.base_provider import BaseLLMProvider, LLMResponse

class MyProvider(BaseLLMProvider):
    def __init__(self, config):
        self.config = config
        self.model = config.llm.my_provider.model

    @property
    def provider_name(self):
        return "my_provider"

    async def complete(self, system_prompt, user_message, response_format="json",
                       max_tokens=1000, temperature=0.1):
        # Call your AI provider's API here
        # Parse the response
        # Return LLMResponse
        return LLMResponse(
            content=response_text,
            provider="my_provider",
            model=self.model,
            tokens_used=token_count,
            latency_ms=elapsed_ms
        )

    async def health_check(self):
        # Return True if the provider is reachable
        try:
            await self.complete("test", "ping", max_tokens=10)
            return True
        except Exception:
            return False
```

### Step 2: Add to Provider Factory

Add one `case` to `llm/provider_factory.py`:

```python
case "my_provider":
    from llm.providers.my_provider import MyProvider
    return MyProvider(config)
```

### Step 3: Add Config

In `backend/config.yaml`:

```yaml
llm:
  my_provider:
    enabled: true
    model: "my-model-v1"
    api_base: "https://api.myprovider.com/v1"
```

In `backend/.security.yml`:

```yaml
my_provider:
  api_key: "your-key-here"
```

### Step 4: Activate

In `backend/config.yaml`:

```yaml
llm:
  active_provider: "my_provider"
```

Restart the server. No other files need to change.

---

## 16. The Web UI Dashboard

CHAI includes a modern **React-based web dashboard** that runs alongside the MCP server. You can use it to manage sessions, run scans, view findings, and monitor everything in real time — no MCP client required.

### What Is the Web UI?

The Web UI is a single-page application (built with **Vite + React + TypeScript + Tailwind CSS + Recharts**) that connects to the backend via REST API and WebSocket. It provides a visual interface for everything CHAI can do.

### How to Access It

When you start the server:

```bash
cd backend
python main.py --transport streamable-http
```

Two things start automatically:

1. **MCP server** on port `9010` (for MCP clients)
2. **Web UI** on port `8060` (for your browser)

Open your browser to: **`http://localhost:8060`**

### Web UI Pages

| Page               | What You Can Do                                                                                       |
| ------------------ | ----------------------------------------------------------------------------------------------------- |
| **Dashboard**      | See total sessions, active scans, findings count, severity doughnut chart, session activity bar chart |
| **Sessions**       | Create new sessions, view all sessions, stop running scans, click into session details                |
| **Session Detail** | View session info, findings breakdown, **live scan logs** (WebSocket-streamed), AI decisions history  |
| **Findings**       | Filter by severity (Critical/High/Medium/Low/Info), filter by session, view evidence and remediation  |
| **Tools**          | Run any of 15+ security tools manually with custom parameters, execute custom commands                |
| **Reports**        | Generate markdown reports, preview in browser, download to disk                                       |
| **Config**         | View server config, active LLM provider, loaded plugins, built-in tools list                          |

### Live Logs / Real-Time Scanning

The Web UI uses **WebSocket** connections to show scan progress in real time:

- When you start an autonomous scan from a session detail page, the UI shows a live progress bar
- Log lines stream in as tools execute
- Findings count updates automatically
- You can emergency-stop the scan with one click

### How the Web UI Fits the Architecture

```
Your Browser
    |
    | HTTP / WebSocket
    v
+----------------------------------+
|   FastAPI Web Server (port 8060) |
|   - REST API for CRUD            |
|   - WebSocket for live logs        |
|   - Serves React SPA               |
+----------------------------------+
    |
    | Same process — shared AppContext
    v
+----------------------------------+
|   CHAI MCP Server (port 9010)    |
|   - AI Planner                    |
|   - Execution Loop                |
|   - SQLite (sessions, findings)   |
+----------------------------------+
```

### Web UI Development (Optional)

If you want to modify the UI:

```bash
cd ui
npm install
npm run dev   # hot-reload dev server on http://localhost:5240
```

The dev server proxies `/api` and `/ws` to the backend on `:8060` automatically.

To build for production:

```bash
cd ui
npm run build   # outputs static files to ui/dist/
```

The backend auto-detects `ui/dist/` and serves it as the static SPA.

### Disabling the Web UI

If you only want the MCP server (no web dashboard):

```bash
cd backend
python main.py --transport streamable-http --no-web
```

Or set in `backend/config.yaml`:

```yaml
server:
  web_enabled: false
```

---

## 17. Windows + WSL Support

CHAI is built around Linux security tools (nmap, sqlmap, nuclei, etc.). When you run CHAI on **Windows**, it can transparently route all commands into **WSL (Windows Subsystem for Linux)** so everything still works.

### What Is WSL?

**WSL** lets you run a full Linux environment inside Windows — without a virtual machine. It's like having Ubuntu (or Debian, Kali, etc.) as an app on your Windows PC.

**Why CHAI needs it:**

- CHAI's tools are Linux binaries (`nmap`, `sqlmap`, `nuclei`, `whatweb`, etc.)
- Windows does not have these tools natively
- WSL gives CHAI a Linux shell where all these tools can be installed and run

### How WSL Routing Works

```
You run CHAI on Windows
    |
    v
CHAI detects: "This is Windows, WSL is available"
    |
    v
Every Linux command is wrapped:
    "nmap -sV target.com"
    becomes:
    "wsl.exe -d Ubuntu -u pentester bash -c 'nmap -sV target.com'"
    |
    v
Command runs inside WSL, result comes back to CHAI
```

**Path conversion happens automatically:**

- `C:\Users\foo\results` → `/mnt/c/Users/foo/results`
- `D:\opt\kb` → `/mnt/d/opt/kb`
- Relative paths with `\` → `/`

### Enabling WSL in CHAI

#### Step 1: Install WSL and a Linux distro

```powershell
# In Windows PowerShell (as Administrator)
wsl --install -d Ubuntu-22.04
# Restart your PC when prompted
```

Then install pentest tools inside WSL:

```bash
# Inside WSL (Ubuntu terminal)
sudo apt-get update
sudo apt-get install -y nmap sqlmap whatweb whois dnsutils curl wget gobuster ffuf
```

#### Step 2: Configure CHAI

**`backend/config.yaml`:**

```yaml
wsl:
  enabled: true # Turn on WSL routing
  distro_name: "Ubuntu-22.04" # Your WSL distro name (blank = default)
  username: "pentester" # User to run commands as inside WSL
  auto_install_missing: true # Auto-install missing tools via apt-get
  mount_path_prefix: "/mnt" # Where Windows drives appear in WSL
  default_shell: "bash" # Shell to use inside WSL
```

**`backend/.security.yml` (for sensitive credentials):**

```yaml
wsl:
  username: "pentester" # Optional: override WSL user
  password: "" # Only needed for SSH-based remote WSL
  ssh_key_path: "" # SSH key for remote WSL instances
  os_details: "Ubuntu-22.04" # For documentation/reference
```

#### Step 3: Run CHAI normally

```powershell
cd backend
python main.py --transport streamable-http
```

All Linux commands will now execute inside WSL automatically. You do not need to change any tool calls or scan scripts.

### What Happens Without WSL?

If you run CHAI on Windows **without** WSL:

- Linux commands like `nmap`, `sqlmap`, `nuclei` will fail with "command not found"
- The **fallback engine** (see Section 18) will try to search the web for Windows alternatives
- Results will be limited because most pentest tools are Linux-only

### Plugins and WSL

When WSL is enabled:

- Plugin loader checks for binaries **inside WSL** too (not just Windows PATH)
- Example: `feroxbuster` is checked with `wsl which feroxbuster`
- If missing and `auto_install_missing` is true, CHAI attempts to install it via `apt-get`

### Advanced: Remote WSL via SSH

If your WSL instance runs on a different machine:

```yaml
wsl:
  enabled: true
  use_ssh: true
  username: "pentester"
  # SSH key goes in backend/.security.yml
```

---

## 18. The Fallback & Self-Recovery Engine

What happens when a tool fails? Without help, the scan stops and returns an error. With CHAI's **Fallback Engine**, the tool analyzes the failure, searches the web for fixes, and **retries automatically**.

### Why This Exists

In the real world, tools fail for many reasons:

- A required binary is not installed (`nmap: command not found`)
- A Python module is missing (`No module named 'lxml'`)
- Permissions are wrong (`Permission denied`)
- A configuration is broken

Instead of stopping and waiting for a human to fix it, CHAI tries to fix it **itself**.

### How It Works — The 6-Step Recovery Loop

```
Step 1: Tool fails (non-zero exit code, timeout, or error)
         |
Step 2: Fallback Engine analyzes the error
         |  Category: missing_tool, permission_error, network_error,
         |            syntax_error, missing_dependency, crash, wsl_error
         |
Step 3: Search the web via DuckDuckGo
         |  Query: "how to install nmap on Windows"
         |  Query: "nmap command not found WSL install"
         |
Step 4: Extract fixes from search results
         |  Found: "sudo apt-get install -y nmap"
         |
Step 5: Apply the fix (through safety policy, then execute)
         |  Running: sudo apt-get install -y nmap
         |
Step 6: Retry the original command
         |  Success! Return result + recovery logs.
```

### Error Categories the Engine Understands

| Category               | Trigger Keywords                                             | Typical Fix                                  |
| ---------------------- | ------------------------------------------------------------ | -------------------------------------------- |
| **missing_tool**       | `not found`, `command not found`, `no such file`             | Install the binary via package manager       |
| **permission_error**   | `permission denied`, `access is denied`                      | Use `sudo`, fix `chmod`/`chown`              |
| **network_error**      | `could not resolve`, `connection refused`, `timeout`         | Check network / DNS / target availability    |
| **syntax_error**       | `unrecognized option`, `invalid argument`, `bad usage`       | Search for correct command syntax            |
| **missing_dependency** | `no module named`, `library not found`, `missing dependency` | Install Python/module/library                |
| **crash**              | `segmentation fault`, `core dumped`, `abort`                 | Search for crash fixes or workarounds        |
| **wsl_error**          | `wsl`, `linux subsystem`                                     | Fix WSL configuration or install tool in WSL |

### What Gets Logged

Every recovery attempt produces a **RecoveryLog** with:

- `step` — what was tried (error_analysis, web_search, fix_extraction, apply_fix, retry_execution)
- `status` — attempted / success / failed / skipped
- `details` — commands run, return codes, search results
- `error` — any failure reason

These logs are attached to the tool result under `_recovery_logs` and also written to the audit log.

### Example: Automatic Recovery in Action

```python
# You call:
scan_vulnerabilities(session_id="sess-123", target="https://target.com", scanner="nuclei")

# What happens internally:
# 1. CHAI runs: nuclei -u https://target.com -silent -jsonl
# 2. Result: returncode=127, stderr="nuclei: command not found"
# 3. Fallback engine triggers:
#    - Analyzes: category="missing_tool", missing_tool="nuclei"
#    - Searches: "how to install nuclei on Ubuntu"
#    - Extracts: "sudo apt-get install nuclei" or "go install ..."
#    - Applies: runs install command through safety policy
#    - Retries: nuclei -u https://target.com -silent -jsonl
# 4. If retry succeeds:
#    - Result returned with _recovered=True and full _recovery_logs
# 5. If retry fails:
#    - Original error returned with _recovered=False and all attempted steps logged
```

### Web Search Details

**Primary search:** Uses the `duckduckgo-search` Python package (fast, no API key needed)

**Fallback search:** If the package is not installed, CHAI falls back to a lightweight HTTP scraper that queries DuckDuckGo HTML directly.

**Search queries are context-aware:**

- They include the tool name, error message, and operating system
- On Windows with WSL, queries target WSL-specific install instructions
- The engine searches 3 targeted queries per failure and keeps the top 3 results per query

### Safety During Recovery

Every fix goes through the same **safety policy** as normal commands:

- Global denylist checked (can't accidentally run `rm -rf /`)
- Scope checking enforced
- Rate limiting applied
- Audit logging records every recovery attempt

**The engine will NEVER:**

- Execute a fix that fails safety validation
- Retry more than the configured `max_retries` (default: 2)
- Install unsigned or untrusted software (only uses standard package managers)

### Configuration

**`backend/config.yaml`:**

```yaml
# WSL auto-install is configured in the wsl section
wsl:
  auto_install_missing: true # Allow automatic package installation in WSL
```

**`config.py` internal setting:**

```python
fallback_engine = FallbackEngine(
    config=config,
    process_controller=process_controller,
    safety_policy=safety_policy,
    wsl_adapter=wsl_adapter,
    max_retries=2,             # How many recovery attempts per tool failure
)
```

### When Fallback Is Triggered

The fallback engine runs **automatically** when:

- A tool returns a non-zero exit code
- A command times out
- An exception occurs during execution

It is **silent** when the original command succeeds — no extra searches, no delays.

### Integration with WSL

When WSL is active and a tool is missing:

1. The fallback engine detects the missing binary
2. It adds a WSL-specific fix: `sudo apt-get install -y <tool>`
3. The fix is executed **inside WSL** via the WSL adapter
4. The retry also runs inside WSL

This means a Windows user can start CHAI with an empty WSL distro, and CHAI will **automatically install missing pentest tools** as they are needed.

---

## 19. Glossary

| Term                  | Meaning                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| **MCP**               | Model Context Protocol — a standard for AI tools to talk to external services  |
| **LLM**               | Large Language Model — an AI like GPT-4, Claude, etc.                          |
| **CVSS**              | Common Vulnerability Scoring System — 0 to 10 severity score                   |
| **SQLi**              | SQL Injection — attacking a database through user input                        |
| **XSS**               | Cross-Site Scripting — injecting JavaScript into web pages                     |
| **SSRF**              | Server-Side Request Forgery — making the server request internal resources     |
| **IDOR**              | Insecure Direct Object Reference — accessing other users' data by changing IDs |
| **BOLA**              | Broken Object Level Authorization — same as IDOR but in API context            |
| **JWT**               | JSON Web Token — a token format used for authentication                        |
| **CORS**              | Cross-Origin Resource Sharing — controls which websites can access an API      |
| **CSP**               | Content Security Policy — controls what resources a page can load              |
| **HSTS**              | HTTP Strict Transport Security — forces HTTPS                                  |
| **CTE**               | Common Table Expression — a SQL feature for recursive queries                  |
| **BM25**              | Best Matching 25 — a ranking algorithm for keyword search                      |
| **firejail**          | A Linux sandboxing program that restricts what processes can do                |
| **cgroups**           | Linux Control Groups — kernel feature for limiting process resources           |
| **Tier 1**            | Passive/safe tools (WHOIS, DNS)                                                |
| **Tier 2**            | Active but standard tools (nmap, nuclei, sqlmap)                               |
| **Tier 3**            | Exploitation tools (Metasploit, reverse shells)                                |
| **Playbook**          | A pre-defined test plan — what to test and in what order                       |
| **Finding**           | A discovered vulnerability with evidence and severity                          |
| **Session**           | A single penetration test engagement — from start to report                    |
| **Scope**             | The list of domains/IPs you are authorized to test                             |
| **Embedding**         | A numerical representation of text (used for semantic search)                  |
| **Vector search**     | Finding similar content using mathematical distance between embeddings         |
| **stdio**             | Standard input/output — a way for processes to communicate                     |
| **Sandbox**           | A restricted execution environment that limits what a program can do           |
| **Audit log**         | A permanent, tamper-proof record of all actions taken                          |
| **WSL**               | Windows Subsystem for Linux — runs Linux binaries on Windows                   |
| **Fallback engine**   | Self-recovery system that diagnoses failures, searches the web, and retries    |
| **Recovery log**      | Immutable record of each step in an automatic recovery attempt                 |
| **DuckDuckGo search** | Privacy-focused web search used by the fallback engine to find fixes           |
| **Path conversion**   | Translating Windows paths (`C:\foo`) to WSL paths (`/mnt/c/foo`)               |
| **Auto-install**      | Automatically installing missing tools via package managers when needed        |
