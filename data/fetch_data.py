"""Optional data fetch helper for larger recon wordlists and pattern packs.

This is intentionally opt-in: a fresh clone still works with the bundled small defaults
in ``data/wordlists/common-small.txt`` and ``data/gf_patterns/*.json``. Users who have
space for a richer corpus can point ``config/config.yaml`` or the CLI at a larger file.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from urllib.request import urlopen

REPO_ROOT = Path(__file__).resolve().parent.parent


def _download(url: str, destination: Path) -> None:
    """Download a file to disk and create any missing parent directories."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(url, timeout=30) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def fetch_wordlist(kind: str) -> Path:
    """Fetch a larger optional wordlist for users who want richer directory discovery."""
    if kind == "seclists-common":
        repo_root = REPO_ROOT / "data" / "wordlists"
        dest = repo_root / "common-seclists.txt"
        url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        _download(url, dest)
        return dest

    raise ValueError(f"Unsupported wordlist kind: {kind}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Optionally fetch a larger offline-data bundle for recon runs.")
    parser.add_argument("--wordlist", choices=["seclists-common"], default=None, help="Fetch a larger bundled wordlist when needed.")
    parser.add_argument("--patterns", default=None, help="Reserved for future pattern-pack downloads; still optional.")
    args = parser.parse_args()

    if args.wordlist:
        path = fetch_wordlist(args.wordlist)
        print(f"Downloaded {args.wordlist} to {path}")
        return

    if args.patterns:
        print("Pattern packs are optional; the bundled minimal defaults are still used by default.")
        return

    print("No optional data requested. The bundled starter files in data/ are still in use.")


if __name__ == "__main__":
    main()
