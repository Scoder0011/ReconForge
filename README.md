# ReconForge

ReconForge is a local recon automation toolkit for authorized security testing.
Use it only against assets you own or are explicitly authorized to assess, and
follow the target program's rules of engagement.

## Requirements

- Python 3.10 or newer
- Linux, macOS, or WSL2 (native Windows is not supported)
- Internet access for the recon tools and passive data sources you choose to use

ReconForge calls external command-line tools. Some may already be installed;
others can be offered for installation when you start a scan. Tool installation
is optional: you can decline and the scan will continue with available tools.
Never run an installer with `sudo` unless you understand and explicitly approve
the exact command.

## Install

Open a terminal in the ReconForge project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Windows, use WSL2 and run these commands from the project directory inside
your WSL filesystem.

## Configure scope

The CLI uses `config/scope.yaml` by default if that file exists. Review it before
scanning. The example configuration is [config/scope.example.yaml](config/scope.example.yaml).
Set the root target and the exact in-scope/out-of-scope patterns according to
your authorization.

Active stages, including permutation/bruteforce and other active checks, require
`allow_active_scans: true` in the scope configuration. They are disabled by
default. Vulnerability scanning has a separate `allow_vuln_scans` authorization
setting and is also subject to active-scan authorization. A UI consent flag does
not override those gates. Do not enable either setting unless the program
explicitly authorizes that activity.

If you want to use another scope file, pass it with `--scope`:

```bash
python run.py -d example.com --scope /path/to/authorized-scope.yaml
```

## Start the web dashboard

In the first terminal, from the project directory (with the virtual environment
activated), start the local API and dashboard:

```bash
python run.py --serve
```

Keep this terminal open while using the dashboard. Open
<http://127.0.0.1:8000> in your browser. The API explorer is at
<http://127.0.0.1:8000/docs>. Stop the server with `Ctrl+C`.

The server binds to `127.0.0.1` only. Do not expose it on a public or LAN
interface. The dashboard can show CLI scan history, live progress events,
available results, reports, and tool status. The API does **not** start or
cancel scans and does not install tools.

## Run a scan

Open a second terminal in the project directory and activate the same virtual
environment. Start a scan only for a target covered by your authorization:

```bash
python run.py -d example.com
```

The CLI checks required tools and may ask whether to install missing ones.
Decline to continue with the tools already available. To skip the installation
prompt:

```bash
python run.py -d example.com --no-install
```

Other useful options:

```bash
python run.py -d example.com --scope config/scope.yaml
python run.py -d example.com --git-repo /path/to/local/repository
python run.py --version
```

`--git-repo` audits an existing local repository; it does not accept a remote
repository URL. Do not use `-y` unless you intentionally want the CLI to install
missing tools without prompting.

The scan runs in the terminal. The dashboard displays its progress and results
because both processes use the same local scan-history database. Start the scan
after the server is running if you want to follow its progress live. Older scans
may not have persisted progress events.

## View results and reports

In the dashboard, open **Dashboard** to see scan history and select **Live
progress** for a running scan. When a CLI scan finishes, its results are
available to browse and its Markdown/HTML reports are generated in that scan's
output directory. The report link is not available until the scan completes.

Scan files are written under:

```text
output/<domain>/<UTC-timestamp>/
```

The scan history database is `output/scans.sqlite3`. Removing a scan from
dashboard history does not remove its output directory. You can also use the
paths printed by the CLI at the end of a run.

## Troubleshooting

- **Dashboard does not open:** make sure `python run.py --serve` is still
  running, then visit `http://127.0.0.1:8000`.
- **Report says it is not ready:** reports are generated after the CLI scan
  finishes. Check the scan's status in the dashboard or the scan terminal.
- **A stage reports zero results after a tool timeout/failure:** this does not
  prove the target has no hosts. Check the stage warning and its raw output in
  the scan directory. Missing tools, network conditions, service limits, and
  large candidate lists can affect results.
- **A tool is missing:** use the dashboard's Tools page to check status, or
  follow the tool's official installation instructions. Tool installation is
  not exposed through the web API.
- **Port 8000 is already in use:** stop the other local server using that port
  before starting ReconForge.

## Responsible use

ReconForge is intended for authorized security testing only. Passive discovery
can query third-party data sources, and active stages contact target systems.
Confirm that both activities are permitted by the relevant rules before
running them. Scope exclusions and authorization gates should not be bypassed.
