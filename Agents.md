# ReconForge: Project Context

ReconForge is a LOCAL web-bug-bounty recon automation tool. The user gives ONE domain; the tool checks for / installs the required recon tools, runs a 13-stage pipeline (parallel inside each stage, stages in order), stores normalized results in SQLite, and shows them live in a local web UI and saves them as report files.

The repo folder tree already exists (all folders/files created, mostly empty). Fill in the existing files; only create new files when truly necessary, and tell me when you do.

## Tech stack
- Python 3.10+, asyncio, FastAPI + uvicorn, websockets, pydantic v2, PyYAML, Jinja2, sqlite3 (stdlib), pytest.
- Frontend: plain HTML/CSS/vanilla JS only. No build step, no npm, no frameworks.
- External recon tools are called as subprocesses. NEVER reimplement them.

## Hard rules (apply to every task)
1. SECURITY: never use `shell=True`. Run tools with `asyncio.create_subprocess_exec` and an args LIST. Validate the target domain with a strict regex (no spaces, no shell metacharacters, valid FQDN) before it goes anywhere near a command.
2. SCOPE GUARD: every target (domain, subdomain, IP, URL) must pass `core/scope.py` before any ACTIVE tool touches it. Passive tools query third parties; active tools touch the target. Out-of-scope = dropped and logged, never scanned.
3. The web backend binds to 127.0.0.1 ONLY. Never 0.0.0.0. Reject non-localhost Host/Origin headers.
4. Active stages (bruteforce, ports, content discovery, nuclei, etc.) require explicit authorization: CLI flag `--i-have-authorization` or a checkbox in the UI. Without it, run passive tools only.
5. Never run `sudo` silently. If a tool or install needs root, print the exact command and ask for confirmation (or skip with a clear warning).
6. A missing/failed tool must NEVER crash the pipeline. Mark it skipped/failed with the reason, continue.
7. Every tool's untouched raw output is saved under `output/<domain>/<timestamp>/raw/<stage>/<tool>.*`.
8. Add type hints and docstrings. Keep functions small. Use `logging` (via core/logger.py), not print.
9. Never hardcode API keys. Read from `config/api_keys.yaml` (gitignored) or env vars. Add secrets and `output/` to .gitignore.
10. Cross-platform: target Linux/macOS/WSL. On native Windows, detect it and print a message recommending WSL2 or Docker.

## Tool registry format (one YAML per tool in tools_registry/<stage>/)
```yaml
name: subfinder
stage: 01_subdomain_passive
description: Passive subdomain enumeration from many public sources
kind: passive                    # passive | active
profiles: [quick, full, stealth] # which profiles enable this tool
check:
  cmd: ["subfinder", "-version"]
  binary: subfinder              # used with shutil.which
install:                         # ordered fallbacks; first that works wins
  - method: go
    package: github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  - method: apt
    package: subfinder
requires_root: false
requires_api_keys: []            # e.g. [chaos, github]; skipped (not failed) if missing and tool is useless without them
input_type: domain               # domain | subdomains_file | hosts_file | ips_file | urls_file | none
run:
  args: ["subfinder", "-d", "{target}", "-all", "-silent", "-o", "{out_file}"]
  stdin_input: false             # true = pipe {input_file} contents to stdin
output:
  file: "{out_file}"             # or "stdout"
  parser: plain_lines            # name of a parser in parsers/
  produces: subdomains           # subdomains | resolved | live_hosts | ports | urls | js_endpoints | params | findings | screenshots | secrets | osint
timeout: 900                     # seconds
retries: 1
rate_limit_arg: ["-rl", "{rate}"] # optional; appended when a rate limit is configured
```
Placeholders: {target} {input_file} {out_file} {out_dir} {wordlist} {resolvers} {threads} {rate}.

## The 13 stages and their data flow
| # | Stage | Input | Output |
|---|-------|-------|--------|
| 01 | subdomain_passive | domain | subdomains |
| 02 | subdomain_bruteforce (+permutations) | domain + known subdomains + wordlist + resolvers | new subdomains |
| 03 | dns | all subdomains | resolved hosts (A/AAAA/CNAME/MX/TXT/NS), IPs, AXFR attempt results; keep only resolving hosts |
| 04 | http_probing | resolved hosts | live URLs (status, title, tech, server, WAF) |
| 05 | ports_infra | resolved IPs/hosts | open ports + services, ASN/CIDR info, TLS cert info (SAN names feed back as new subdomains) |
| 06 | screenshots | live URLs | PNG files |
| 07 | url_collection | domain + live hosts | URLs (archive + crawled) |
| 08 | javascript | URLs | JS files, endpoints, secrets found in JS |
| 09 | parameters | URLs | params, gf-categorized URLs (xss/sqli/ssrf/lfi/redirect...), deduped via uro |
| 10 | content_discovery | live URLs | discovered paths/files |
| 11 | vuln_checks | live URLs + hosts | findings (nuclei, takeover, XSS, CORS) |
| 12 | cloud_secrets | domain / company keyword | open buckets, leaked secrets in repos |
| 13 | osint | domain | emails, names, whois, Shodan/Censys/FOFA/SecurityTrails data |

Notes:
- Stage 13 is passive and may run concurrently with Stage 01; its discovered hostnames merge into the subdomain set.
- Stages 01-03 form the "subdomain phase": passive -> merge/dedupe -> bruteforce + permutations -> resolve everything with dnsx/puredns -> keep resolving hosts only.
- ASN/CIDR ranges discovered in stage 05 are REPORTED only. Never scan an ASN range unless the user explicitly adds it to scope.
- All tools in a stage run in parallel (bounded by config concurrency). Overlapping tools are intentional; the union is the result and the DB records WHICH tools found each item.

## Normalized data model (SQLite, core/db.py)
Tables: scans, tool_runs (tool, stage, status, start/end, exit_code, error, raw_path, item_count), subdomains, hosts (ip, records), live_hosts, ports, urls, js_endpoints, params, findings, screenshots, secrets, osint, and an `item_sources` table linking each item to the tool(s) that found it.

## Config
config/config.yaml (threads, timeouts, rate limits, output dir, concurrency), config/profiles/{quick,full,stealth}.yaml (which tools/stages are enabled; stealth = passive only), config/scope.example.yaml (in_scope domains/wildcards, out_of_scope exclusions, allowed_ports optional, notes), config/api_keys.example.yaml.