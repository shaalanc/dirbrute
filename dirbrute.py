#!/usr/bin/env python3
"""
dirbrute - directory/endpoint brute-forcer with soft-404 detection.

Same authorization model as reconwrap's scan command: active HTTP
enumeration requires an explicit target and a typed confirmation, since
this sends many requests against a live server, not a passive lookup.

Soft-404 handling: many apps return HTTP 200 for missing paths along
with a custom "not found" page, instead of a real 404 status. A naive
brute-forcer treats every 200 as a hit and drowns real findings in
false positives. This tool baselines against a random, definitely
nonexistent path first, and compares every result against that
baseline's status code and response length before calling it a hit.

Usage:
    python dirbrute.py http://localhost:3000
    python dirbrute.py http://localhost:3000 --wordlist custom.txt --yes
"""

import argparse
import concurrent.futures
import os
import random
import re
import string
import sys
import time
from datetime import datetime

import requests

WORDLIST_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists")

DEFAULT_WORDLIST = [
    "admin", "login", "backup", "config", ".env", ".git", "api",
    "ftp", "uploads", "assets", "old", "test", "dev", "staging",
    "robots.txt", "sitemap.xml", "server-status", ".well-known",
    "swagger", "swagger-ui", "graphql", "rest", "encryptionkeys",
    "administration", "dashboard", ".htaccess", "wp-admin",
]


def derive_output_filename(target: str) -> str:
    """
    Builds a filename like 'localhost_3000_20260721_143205.txt' from the
    target and the current time. Colons (from ports) and slashes aren't
    valid in Windows filenames, so anything outside a safe character set
    gets replaced rather than letting the write fail partway through a run.
    """
    domain = re.sub(r"^https?://", "", target).rstrip("/")
    safe_domain = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe_domain}_{timestamp}.txt"


def list_available_wordlists() -> list[str]:
    if not os.path.isdir(WORDLIST_DIR):
        return []
    return sorted(f for f in os.listdir(WORDLIST_DIR) if os.path.isfile(os.path.join(WORDLIST_DIR, f)))


def get_baseline(base_url: str, timeout: int) -> tuple[int, int]:
    """
    Requests a definitely-nonexistent path to learn what a 'not found'
    response actually looks like on this server: its status code and
    response length.
    """
    junk = "".join(random.choices(string.ascii_lowercase, k=20))
    resp = requests.get(f"{base_url}/{junk}", timeout=timeout, allow_redirects=False)
    return resp.status_code, len(resp.content)


def check_path(base_url: str, path: str, baseline: tuple[int, int], timeout: int) -> dict | None:
    url = f"{base_url}/{path}"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None

    base_status, base_len = baseline
    matches_baseline = resp.status_code == base_status and abs(len(resp.content) - base_len) < 5

    if resp.status_code == 404 or matches_baseline:
        return None  # matches the "not found" signature, not a real hit

    return {"path": path, "status": resp.status_code, "length": len(resp.content), "url": url}


def confirm_scan(target: str, auto_yes: bool) -> bool:
    print(f"\n[!] About to actively brute-force paths against: {target}")
    print("[!] This sends many requests quickly. Only run against hosts you own")
    print("[!] or are explicitly authorized to test.\n")
    if auto_yes:
        return True
    answer = input(f"Type 'yes' to confirm you're authorized to test {target}: ").strip().lower()
    return answer == "yes"


def load_wordlist(name_or_path: str | None) -> list[str]:
    if not name_or_path:
        return DEFAULT_WORDLIST

    # Try it as a direct path first, then as a short name inside wordlists/
    candidates = [name_or_path, os.path.join(WORDLIST_DIR, name_or_path)]
    for path in candidates:
        if os.path.isfile(path):
            with open(path) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"[!] Couldn't find wordlist '{name_or_path}' as a path or in {WORDLIST_DIR}/", file=sys.stderr)
    available = list_available_wordlists()
    if available:
        print(f"[!] Available: {', '.join(available)}", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Directory/endpoint brute-forcer with soft-404 detection")
    parser.add_argument("target", nargs="?")
    parser.add_argument(
        "--wordlist",
        help="a filename in wordlists/ (e.g. --wordlist common.txt), or a full path to any file, one path per line",
    )
    parser.add_argument("--list-wordlists", action="store_true", help="show available wordlists and exit")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to wait between requests, per thread")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--yes", action="store_true", help="skip the interactive confirmation prompt")
    parser.add_argument("--output", help="output filename (default: <domain>_<timestamp>.txt, auto-generated)")
    parser.add_argument("--no-output", action="store_true", help="skip writing a results file, print to console only")
    args = parser.parse_args()

    if args.list_wordlists:
        available = list_available_wordlists()
        if available:
            print("Available wordlists in wordlists/:")
            for w in available:
                print(f"  {w}")
        else:
            print(f"No wordlists found in {WORDLIST_DIR}/. Drop .txt files there, one path per line.")
        return

    if not args.target:
        parser.error("target is required unless using --list-wordlists")

    target = args.target.rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    if not confirm_scan(target, args.yes):
        print("[!] Not confirmed, aborting.")
        sys.exit(1)

    print("[*] Baselining a known-missing path...")
    try:
        baseline = get_baseline(target, args.timeout)
    except requests.RequestException as e:
        print(f"[!] Couldn't reach target: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[*] Baseline: status={baseline[0]} length={baseline[1]}\n")

    wordlist = load_wordlist(args.wordlist)
    print(f"[*] Testing {len(wordlist)} paths with {args.threads} threads...\n")

    def worker(word):
        if args.delay:
            time.sleep(args.delay)
        return check_path(target, word, baseline, args.timeout)

    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        for result in executor.map(worker, wordlist):
            if result:
                findings.append(result)
                print(f"  [{result['status']}] /{result['path']}  ({result['length']} bytes)")

    print(f"\n[*] Done. {len(findings)} finding(s) out of {len(wordlist)} paths tested.\n")

    if not args.no_output:
        output_path = args.output or derive_output_filename(target)
        with open(output_path, "w") as f:
            f.write(f"Target: {target}\n")
            f.write(f"Scanned at: {datetime.now().isoformat()}\n")
            f.write(f"Baseline: status={baseline[0]} length={baseline[1]}\n")
            f.write(f"Wordlist: {len(wordlist)} entries\n\n")
            for r in findings:
                f.write(f"[{r['status']}] {r['url']}  ({r['length']} bytes)\n")
            f.write(f"\nTotal findings: {len(findings)} / {len(wordlist)} tested\n")
        print(f"[*] Results saved to {output_path}")


if __name__ == "__main__":
    main()