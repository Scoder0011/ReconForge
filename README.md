# ReconForge

ReconForge is a local recon automation toolkit for authorized security testing.

Responsible-use notice: use this tool only against in-scope assets you own or are
explicitly authorized to assess in writing. Do not use it for unauthorized
scanning, credentialed attacks, or any activity outside the user-defined scope.

Quickstart

1. Clone the repo.
2. Run the scanner once: `python run.py -d yourdomain.com`
3. If any required recon tools are missing, the CLI will prompt you to install them.
4. Use `-y`/`--yes` in CI or unattended runs, or `--no-install` if you want to manage dependencies yourself.

This command is intentionally self-sufficient: it loads the relevant registry,
checks the required tools, installs anything missing that can be installed
automatically, then runs the first recon stages.

An optional local Git history audit can be requested with
`python run.py -d yourdomain.com --git-repo /path/to/local/repository`.
Remote repository URLs are not accepted; secret findings in the normalized
summary are redacted. Cloud-provider bucket-name enumeration is intentionally
not included because it generates requests to third-party providers.

## Local API

`python run.py --serve` starts the local API at
`http://127.0.0.1:8000` and its API explorer at `/docs`. It exposes stored CLI
scan history, results, reports, exports, scope settings, and tool availability.
CLI scans persist stage-level progress events to the shared scan-history
database, which the dashboard streams over WebSocket. Events are available for
scans started after this progress feature is added; older scan records do not
have historical progress events. The dashboard can edit scope patterns and
remove scan-history entries. Removing a history entry does not delete that
scan's output files. The API does not provide endpoints to launch/cancel scans
or install tools. API access is restricted to localhost.
