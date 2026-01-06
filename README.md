# Domain Finder(.ai domains)

This repo includes a small script that checks `.ai` domain availability using a
CSV list of words and WHOIS queries.

It outputs a CSV with:

- `word`: input value from the CSV
- `domain`: `<word>.ai`
- `status`: `available`, `taken`, or `error`
- `reason`: a short explanation (WHOIS marker, throttle, etc.)

## Requirements

- Python 3.8+ (system Python is fine)
- `nc` (netcat) on your PATH

## Files

- `check_ai_domains.py` - main script
- `words.csv` - sample list of words (one per row)
- `words_uncommon.csv` - alternate list of uncommon names (optional)

## Quick Start

```bash
python3 check_ai_domains.py words.csv --mode netcat > results.csv
```

## CSV Input

Default format:

```csv
word
ada
arwenbelle
```

Options:

- `--column NAME` - use a named CSV column
- `--column 0` - use a 0-based column index
- `--no-header` - treat first row as data

## Output File (Resume Friendly)

Write to a file and resume later without losing progress:

```bash
python3 check_ai_domains.py words.csv \
  --mode netcat \
  --output results.csv \
  --checkpoint .whois_checkpoint \
  --resume
```

## Throttling / Rate Limits

WHOIS servers can throttle or block high-rate queries. The script can back off
automatically when it detects throttling (e.g., `nc exit 1`, `try again later`,
`whois limit exceeded`).

Recommended settings:

```bash
python3 check_ai_domains.py words.csv \
  --mode netcat \
  --sleep 2 \
  --max-sleep 20 \
  --backoff-factor 2 \
  --throttle-retries 5 \
  --output results.csv \
  --checkpoint .whois_checkpoint \
  --resume
```

Notes:

- `--sleep` is the base delay between requests.
- Backoff increases the delay when throttling is detected.
- `--throttle-retries` controls how many times to retry a domain when throttled.

## Debug Mode

Use `--debug` to print brief diagnostics to stderr:

```bash
python3 check_ai_domains.py words.csv --mode netcat --debug
```

## Common Issues

**All rows show `error, empty response`:**

- Ensure port 43 is reachable from your network.
- Try netcat mode explicitly: `--mode netcat`.

**`nc exit 1` errors mid-run:**

- You are being throttled. Increase `--sleep` and use backoff settings.

**A known available domain shows as `taken`:**

- Check for typos (e.g., `arwenbelle` vs `aarwenbelle`).
- Run a single test with netcat to compare:
  ```bash
  printf "arwenbelle.ai\r\n" | nc -w 5 whois.nic.ai 43
  ```

## Example: Single Word Check

```bash
printf "arwenbelle\n" | python3 check_ai_domains.py /dev/stdin --no-header --mode netcat
```
