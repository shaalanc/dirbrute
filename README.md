# Dirbrute

A fast, accurate directory and endpoint brute-forcer with intelligent soft-404 detection.

## Overview

Dirbrute is a Python tool for discovering hidden directories and endpoints on web servers. Unlike naive brute-forcers that treat every HTTP 200 as a hit, Dirbrute intelligently detects "soft-404" responses—when applications return HTTP 200 with a custom "not found" page instead of a real 404 status code.

By baselining against a random, definitely-nonexistent path first, Dirbrute filters out false positives and gives you real findings.

## Features

- **Soft-404 Detection**: Automatically detects and filters out soft-404 responses
- **Multi-threaded**: Fast parallel scanning with configurable thread count
- **Flexible Wordlists**: Use built-in wordlists or provide your own
- **Configurable**: Control timeout, delay, and output format
- **Safe by Default**: Requires explicit confirmation before scanning

## Requirements

- Python 3.10+
- `requests` library

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd dirbrute

# Install dependencies
pip install requests
```

## Usage

### Basic Usage

```bash
# Scan a target (requires interactive confirmation)
python dirbrute.py http://localhost:3000

# Scan with automatic confirmation (use with caution)
python dirbrute.py http://localhost:3000 --yes

# Scan with a custom wordlist
python dirbrute.py http://localhost:3000 --wordlist common.txt --yes

# Use a full path to a wordlist
python dirbrute.py http://localhost:3000 --wordlist /path/to/wordlist.txt --yes
```

### Available Options

```
positional arguments:
  target                Target URL to scan

optional arguments:
  --wordlist WORDLIST   Wordlist filename in wordlists/ or full path
  --list-wordlists      Show available wordlists and exit
  --threads THREADS     Number of worker threads (default: 10)
  --delay DELAY         Seconds to wait between requests per thread (default: 0.0)
  --timeout TIMEOUT     HTTP request timeout in seconds (default: 8)
  --yes                 Skip interactive confirmation prompt
  --output OUTPUT       Output filename (default: auto-generated)
  --no-output           Print results only, don't write to file
```

### Examples

```bash
# List available wordlists
python dirbrute.py --list-wordlists

# Aggressive scan with 20 threads and custom output
python dirbrute.py http://example.com --threads 20 --output results.txt --yes

# Slow, stealthy scan with 1-second delay between requests
python dirbrute.py http://example.com --threads 5 --delay 1.0 --yes

# Quick check on localhost with timeout of 5 seconds
python dirbrute.py http://localhost:8080 --timeout 5 --yes

# Use a custom wordlist with detailed output
python dirbrute.py http://example.com --wordlist /path/to/custom.txt --yes
```

## Wordlists

Dirbrute includes a default wordlist with common paths:
- `admin`, `login`, `backup`, `config`, `.env`, `.git`, `api`
- `ftp`, `uploads`, `assets`, `old`, `test`, `dev`, `staging`
- `robots.txt`, `sitemap.xml`, `server-status`, `.well-known`
- `swagger`, `swagger-ui`, `graphql`, `rest`, `encryptionkeys`
- `administration`, `dashboard`, `.htaccess`, `wp-admin`

### Custom Wordlists

Place custom wordlists in the `wordlists/` directory:

```bash
# Copy your wordlist
cp /path/to/custom.txt wordlists/custom.txt

# Use it
python dirbrute.py http://example.com --wordlist custom.txt --yes
```

Wordlist format: one path per line, blank lines and lines starting with `#` are ignored.

## Output

Results are automatically saved to a timestamped file like `localhost_3000_20260721_143205.txt` containing:

- Target URL
- Scan timestamp
- Baseline response info
- Found paths with status codes and response lengths
- Total findings summary

Example output:
```
Target: http://example.com
Scanned at: 2026-07-21T14:32:05.123456
Baseline: status=200 length=1234
Wordlist: 25 entries

[200] http://example.com/admin  (2456 bytes)
[403] http://example.com/backup  (512 bytes)
[200] http://example.com/api  (3200 bytes)

Total findings: 3 / 25 tested
```

## Authorization & Safety

This tool sends many HTTP requests to a target server. **Only use it on:**

- Systems you own
- Systems you have explicit written permission to test
- Authorized security assessments and penetration tests

Running this tool against systems without authorization is illegal in most jurisdictions.

The tool requires explicit confirmation before scanning to prevent accidental misuse.

## How Soft-404 Detection Works

1. **Baseline**: Requests a random, definitely non-existent path (e.g., `/{20-char-random-string}`)
2. **Compare**: For each tested path, compares status code and response length against the baseline
3. **Filter**: Treats a response as a "not found" if it matches the baseline signature (same status code and similar length ±5 bytes)
4. **Result**: Only paths that differ from the baseline are reported as findings

This approach accurately finds real endpoints even when applications return HTTP 200 for missing paths.

## Troubleshooting

**"Couldn't reach target"**: Check that the URL is correct and the server is online.

**Too many false positives**: The soft-404 detection may need tuning. Check the baseline output and consider using `--delay` to avoid rate limiting.

**All paths appear as 404**: Verify you're authorized to scan this target and check the baseline response.

## Performance Tips

- Adjust `--threads` based on target capacity (higher = faster but may cause issues)
- Use `--delay` to be stealthy or to avoid triggering rate limits
- Larger wordlists take proportionally longer to test
- Use `--timeout` to skip slow/unresponsive servers quickly

## License

MIT
