-- Knowledge Graph schema for attack chains and techniques

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Attack techniques / nodes
CREATE TABLE IF NOT EXISTS techniques (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    category        TEXT NOT NULL,  -- recon, scan, injection, auth, network, exploit, post_exploit
    description     TEXT,
    prerequisites   TEXT DEFAULT '[]',
    indicators      TEXT DEFAULT '[]',
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    tier            TEXT DEFAULT 'tier1',  -- tier1 | tier2 | tier3
    tags            TEXT DEFAULT '[]'
);

-- Attack chain relationships
CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    from_technique  TEXT NOT NULL,
    to_technique    TEXT NOT NULL,
    condition       TEXT DEFAULT '',  -- when this transition is valid
    probability     REAL DEFAULT 0.5, -- likelihood of successful transition
    FOREIGN KEY (from_technique) REFERENCES techniques(id),
    FOREIGN KEY (to_technique) REFERENCES techniques(id)
);

-- Playbook sections
CREATE TABLE IF NOT EXISTS playbooks (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    test_type       TEXT NOT NULL,
    description     TEXT,
    phases          TEXT DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Insert default techniques (50+ nodes)
INSERT OR IGNORE INTO techniques (id, name, category, description, tier, tags) VALUES
('recon_passive', 'Passive Reconnaissance', 'recon', 'Gather info without touching target', 'tier1', '["recon","passive","osint"]'),
('recon_active', 'Active Reconnaissance', 'recon', 'Direct interaction with target', 'tier1', '["recon","active","scanning"]'),
('dns_enum', 'DNS Enumeration', 'recon', 'Enumerate DNS records and subdomains', 'tier1', '["recon","dns","subdomain"]'),
('whois_lookup', 'WHOIS Lookup', 'recon', 'Query domain registration info', 'tier1', '["recon","whois","osint"]'),
('port_scan_tcp', 'TCP Port Scan', 'scan', 'Scan for open TCP ports', 'tier1', '["scan","port","tcp"]'),
('port_scan_udp', 'UDP Port Scan', 'scan', 'Scan for open UDP ports', 'tier2', '["scan","port","udp"]'),
('service_enum', 'Service Enumeration', 'scan', 'Identify services on open ports', 'tier1', '["scan","service","banner"]'),
('os_fingerprint', 'OS Fingerprinting', 'scan', 'Determine target operating system', 'tier1', '["scan","os","fingerprint"]'),
('web_scan', 'Web Application Scan', 'scan', 'Scan web apps for vulnerabilities', 'tier1', '["scan","web","app"]'),
('ssl_scan', 'SSL/TLS Scan', 'scan', 'Analyze SSL/TLS configuration', 'tier1', '["scan","ssl","tls"]'),
('dir_bruteforce', 'Directory Bruteforce', 'scan', 'Bruteforce directories and files', 'tier2', '["scan","web","directory","bruteforce"]'),
('sqli_test', 'SQL Injection Test', 'injection', 'Test for SQL injection vulnerabilities', 'tier2', '["injection","sql","database"]'),
('xss_test', 'XSS Test', 'injection', 'Test for cross-site scripting', 'tier2', '["injection","xss","web"]'),
('cmd_injection', 'Command Injection', 'injection', 'Test for command injection', 'tier2', '["injection","command","rce"]'),
('xxe_test', 'XXE Test', 'injection', 'Test for XML external entity injection', 'tier2', '["injection","xml","xxe"]'),
('ssrf_test', 'SSRF Test', 'injection', 'Test for server-side request forgery', 'tier2', '["injection","ssrf","web"]'),
('lfi_test', 'LFI Test', 'injection', 'Test for local file inclusion', 'tier2', '["injection","lfi","file"]'),
('rfi_test', 'RFI Test', 'injection', 'Test for remote file inclusion', 'tier2', '["injection","rfi","file"]'),
('nosql_test', 'NoSQL Injection', 'injection', 'Test for NoSQL injection', 'tier2', '["injection","nosql","database"]'),
('ldap_injection', 'LDAP Injection', 'injection', 'Test for LDAP injection', 'tier2', '["injection","ldap","directory"]'),
('auth_bypass', 'Authentication Bypass', 'auth', 'Bypass authentication mechanisms', 'tier2', '["auth","bypass","login"]'),
('session_hijack', 'Session Hijacking', 'auth', 'Hijack user sessions', 'tier2', '["auth","session","hijack"]'),
('password_spray', 'Password Spraying', 'auth', 'Test common passwords against accounts', 'tier2', '["auth","password","bruteforce"]'),
('jwt_analysis', 'JWT Analysis', 'auth', 'Analyze JWT tokens for weaknesses', 'tier2', '["auth","jwt","token"]'),
('oauth_test', 'OAuth Test', 'auth', 'Test OAuth implementation', 'tier2', '["auth","oauth","sso"]'),
('saml_test', 'SAML Test', 'auth', 'Test SAML implementation', 'tier2', '["auth","saml","sso"]'),
('mfa_bypass', 'MFA Bypass', 'auth', 'Bypass multi-factor authentication', 'tier3', '["auth","mfa","bypass"]'),
('privesc_linux', 'Linux Privilege Escalation', 'exploit', 'Escalate privileges on Linux', 'tier3', '["exploit","privesc","linux"]'),
('privesc_windows', 'Windows Privilege Escalation', 'exploit', 'Escalate privileges on Windows', 'tier3', '["exploit","privesc","windows"]'),
('credential_dump', 'Credential Dumping', 'exploit', 'Dump credentials from memory/storage', 'tier3', '["exploit","credential","dump"]'),
('lateral_movement', 'Lateral Movement', 'exploit', 'Move laterally across network', 'tier3', '["exploit","lateral","network"]'),
('persistence', 'Persistence', 'exploit', 'Establish persistent access', 'tier3', '["exploit","persistence","backdoor"]'),
('network_sniff', 'Network Sniffing', 'network', 'Capture network traffic', 'tier2', '["network","sniff","capture"]'),
('arp_spoof', 'ARP Spoofing', 'network', 'Perform ARP spoofing attacks', 'tier2', '["network","arp","spoof"]'),
('dns_spoof', 'DNS Spoofing', 'network', 'Perform DNS spoofing attacks', 'tier2', '["network","dns","spoof"]'),
('mitm_attack', 'MITM Attack', 'network', 'Man-in-the-middle attacks', 'tier3', '["network","mitm","intercept"]'),
('wifi_crack', 'WiFi Cracking', 'network', 'Crack WiFi encryption', 'tier3', '["network","wifi","crack"]'),
('bluetooth_attack', 'Bluetooth Attack', 'network', 'Attack Bluetooth devices', 'tier3', '["network","bluetooth","wireless"]'),
('api_test', 'API Testing', 'scan', 'Test REST/GraphQL APIs', 'tier2', '["scan","api","rest","graphql"]'),
('graphql_introspection', 'GraphQL Introspection', 'scan', 'Extract GraphQL schema', 'tier2', '["scan","graphql","introspection"]'),
('cors_test', 'CORS Test', 'scan', 'Test CORS configuration', 'tier1', '["scan","cors","web"]'),
('csp_test', 'CSP Test', 'scan', 'Test Content Security Policy', 'tier1', '["scan","csp","web"]'),
('header_analysis', 'Security Header Analysis', 'scan', 'Analyze HTTP security headers', 'tier1', '["scan","header","http"]'),
('cookie_analysis', 'Cookie Security Analysis', 'scan', 'Analyze cookie security settings', 'tier1', '["scan","cookie","http"]'),
('crlf_injection', 'CRLF Injection', 'injection', 'Test for CRLF injection', 'tier2', '["injection","crlf","header"]'),
('host_header_attack', 'Host Header Attack', 'injection', 'Test for host header attacks', 'tier2', '["injection","host","header"]'),
('open_redirect', 'Open Redirect', 'injection', 'Test for open redirects', 'tier2', '["injection","redirect","web"]'),
('idor_test', 'IDOR Test', 'auth', 'Test for insecure direct object references', 'tier2', '["auth","idor","access"]'),
('path_traversal', 'Path Traversal', 'injection', 'Test for path traversal', 'tier2', '["injection","path","traversal"]'),
('deserialization', 'Deserialization Attack', 'injection', 'Test for insecure deserialization', 'tier3', '["injection","deserialize","object"]'),
('race_condition', 'Race Condition', 'exploit', 'Test for race conditions', 'tier3', '["exploit","race","timing"]'),
('business_logic', 'Business Logic Flaw', 'exploit', 'Test for business logic flaws', 'tier2', '["exploit","logic","business"]'),
('file_upload', 'File Upload Abuse', 'injection', 'Test for insecure file upload', 'tier2', '["injection","upload","file"]'),
('smtp_enum', 'SMTP Enumeration', 'recon', 'Enumerate SMTP users and config', 'tier1', '["recon","smtp","email"]'),
('snmp_enum', 'SNMP Enumeration', 'recon', 'Enumerate SNMP information', 'tier1', '["recon","snmp","network"]');

-- Insert attack chains
INSERT OR IGNORE INTO attack_chains (from_technique, to_technique, condition, probability) VALUES
('recon_passive', 'recon_active', 'domain identified', 0.9),
('recon_active', 'port_scan_tcp', 'target reachable', 0.95),
('port_scan_tcp', 'service_enum', 'open ports found', 0.9),
('service_enum', 'web_scan', 'web service detected', 0.85),
('service_enum', 'ssl_scan', 'ssl service detected', 0.9),
('web_scan', 'sqli_test', 'dynamic content found', 0.6),
('web_scan', 'xss_test', 'user input found', 0.7),
('web_scan', 'dir_bruteforce', 'web app confirmed', 0.8),
('dir_bruteforce', 'sqli_test', 'parameters found', 0.5),
('dir_bruteforce', 'auth_bypass', 'login page found', 0.6),
('auth_bypass', 'session_hijack', 'session tokens found', 0.5),
('auth_bypass', 'privesc_linux', 'low-priv access gained', 0.3),
('sqli_test', 'cmd_injection', 'sql injection confirmed', 0.4),
('sqli_test', 'credential_dump', 'database access gained', 0.3),
('cmd_injection', 'privesc_linux', 'shell access gained', 0.5),
('cmd_injection', 'lateral_movement', 'internal network access', 0.4),
('xss_test', 'session_hijack', 'cookie theft possible', 0.6),
('ssl_scan', 'network_sniff', 'weak ssl detected', 0.4),
('api_test', 'sqli_test', 'api parameters found', 0.5),
('api_test', 'auth_bypass', 'api auth weak', 0.5),
('header_analysis', 'cors_test', 'cors header present', 0.7),
('header_analysis', 'csp_test', 'csp header present', 0.7),
('cors_test', 'api_test', 'cors misconfigured', 0.6),
('file_upload', 'cmd_injection', 'executable upload allowed', 0.7),
('open_redirect', 'ssrf_test', 'url parameter found', 0.4),
('ssrf_test', 'cmd_injection', 'internal services exposed', 0.3),
('idor_test', 'privesc_linux', 'elevated access possible', 0.3),
('password_spray', 'auth_bypass', 'weak passwords found', 0.4),
('jwt_analysis', 'session_hijack', 'jwt weak signing', 0.5),
('dns_enum', 'port_scan_tcp', 'subdomains found', 0.8),
('whois_lookup', 'dns_enum', 'nameservers identified', 0.7),
('os_fingerprint', 'privesc_linux', 'linux detected', 0.3),
('os_fingerprint', 'privesc_windows', 'windows detected', 0.3);

-- Insert default playbooks
INSERT OR IGNORE INTO playbooks (id, name, test_type, description, phases) VALUES
('web_app_basic', 'Basic Web Application Test', 'web_app', 
 'Standard web application security assessment', 
 '["recon_passive","recon_active","port_scan_tcp","service_enum","web_scan","header_analysis","sqli_test","xss_test","auth_bypass"]'),

('api_security', 'API Security Assessment', 'api', 
 'REST/GraphQL API security testing', 
 '["recon_passive","port_scan_tcp","api_test","auth_bypass","jwt_analysis","sqli_test","idor_test","rate_limit_test"]'),

('network_infra', 'Network Infrastructure Test', 'network', 
 'Internal/external network infrastructure assessment', 
 '["recon_passive","port_scan_tcp","port_scan_udp","service_enum","os_fingerprint","ssl_scan","network_sniff","vuln_scan"]'),

('red_team', 'Red Team Engagement', 'red_team', 
 'Full adversary simulation with persistence', 
 '["recon_passive","recon_active","port_scan_tcp","service_enum","auth_bypass","cmd_injection","privesc_linux","lateral_movement","persistence","credential_dump"]'),

('mobile_app', 'Mobile Application Test', 'mobile', 
 'Mobile app backend and API testing', 
 '["recon_passive","port_scan_tcp","api_test","ssl_scan","auth_bypass","file_upload","sqli_test","xss_test"]');
