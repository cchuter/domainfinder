#!/usr/bin/env python3
import argparse
import csv
import os
import re
import shutil
import socket
import subprocess
import sys
import time

DEFAULT_WHOIS_SERVER = "whois.nic.ai"
HEADER_HINTS = {"word", "words", "name", "domain", "domains"}
AVAILABLE_MARKERS = [
    "NO OBJECT FOUND",
    "NOT FOUND",
    "NO MATCH FOR",
    "DOMAIN NOT FOUND",
    "NO DATA FOUND",
    "OBJECT DOES NOT EXIST",
]
AVAILABLE_REGEXES = [
    r"\bNO\s+OBJECT\s+FOUND\b",
    r"\bDOMAIN\s+NOT\s+FOUND\b",
    r"\bNOT\s+FOUND\b",
    r"\bNO\s+MATCH\s+FOR\b",
    r"\bNO\s+DATA\s+FOUND\b",
    r"\bOBJECT\s+DOES\s+NOT\s+EXIST\b",
]
TAKEN_REGEXES = [
    r"\bDOMAIN\s+NAME\s*:",
    r"\bREGISTRY\s+DOMAIN\s+ID\s*:",
    r"\bREGISTRAR\s*:",
    r"\bNAME\s+SERVER\s*:",
]
THROTTLE_MARKERS = [
    "WHOIS LIMIT EXCEEDED",
    "QUERY LIMIT EXCEEDED",
    "EXCESSIVE QUERIES",
    "TRY AGAIN LATER",
]
THROTTLE_ERROR_HINTS = [
    "NC EXIT 1",
    "TERMS-ONLY RESPONSE",
    "TRY AGAIN",
    "LIMIT",
    "EXCESSIVE",
    "THROTTLE",
]


def iter_words(csv_path, column, no_header):
    with open(csv_path, newline="") as handle:
        if column is None:
            reader = csv.reader(handle)
            for row_idx, row in enumerate(reader, start=1):
                if not row:
                    continue
                value = row[0].strip()
                if row_idx == 1 and not no_header and value.lower() in HEADER_HINTS:
                    continue
                if value:
                    yield row_idx, value
            return

        if column.isdigit():
            col_idx = int(column)
            reader = csv.reader(handle)
            for row_idx, row in enumerate(reader, start=1):
                if not row:
                    continue
                if col_idx >= len(row):
                    print(
                        f"Row {row_idx} has no column index {col_idx}",
                        file=sys.stderr,
                    )
                    continue
                value = row[col_idx].strip()
                if row_idx == 1 and not no_header and value.lower() in HEADER_HINTS:
                    continue
                if value:
                    yield row_idx, value
            return

        reader = csv.DictReader(handle)
        if not reader.fieldnames or column not in reader.fieldnames:
            available = ", ".join(reader.fieldnames or [])
            raise ValueError(
                f"Column '{column}' not found. Available: {available or 'none'}"
            )
        for row_idx, row in enumerate(reader, start=2):
            value = (row.get(column) or "").strip()
            if value:
                yield row_idx, value


def is_valid_label(label):
    if not label:
        return False, "empty label"
    if len(label) > 63:
        return False, "label too long"
    if label.startswith("-") or label.endswith("-"):
        return False, "label starts or ends with '-'"
    if not re.fullmatch(r"[a-z0-9-]+", label):
        return False, "invalid characters"
    return True, ""


def query_whois_socket(domain, server, timeout, family):
    try:
        addrinfos = socket.getaddrinfo(server, 43, family, socket.SOCK_STREAM)
    except Exception as exc:
        return "", str(exc)
    last_error = ""
    saw_empty = False
    for af, socktype, proto, _, sockaddr in addrinfos:
        try:
            with socket.socket(af, socktype, proto) as sock:
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                sock.sendall((domain + "\r\n").encode("ascii"))
                sock.shutdown(socket.SHUT_WR)
                chunks = []
                while True:
                    try:
                        data = sock.recv(4096)
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
            if chunks:
                return b"".join(chunks).decode("utf-8", errors="replace"), ""
            saw_empty = True
        except Exception as exc:
            last_error = str(exc)
    if saw_empty:
        return "", ""
    return "", last_error or "connection failed"


def query_whois_netcat(domain, server, timeout):
    if not shutil.which("nc"):
        return "", "nc not found"
    timeout_arg = str(max(1, int(round(timeout))))
    try:
        result = subprocess.run(
            ["nc", "-w", timeout_arg, server, "43"],
            input=domain + "\r\n",
            text=True,
            capture_output=True,
            timeout=timeout + 2,
            check=False,
        )
    except Exception as exc:
        return "", str(exc)
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if result.returncode != 0:
        return "", stderr.strip() or stdout.strip() or f"nc exit {result.returncode}"
    if not stdout.strip() and stderr.strip():
        return "", stderr.strip()
    return stdout, ""


def classify_response(response):
    head = "\n".join(response.splitlines()[:8])
    for pattern in AVAILABLE_REGEXES:
        if re.search(pattern, head, re.IGNORECASE):
            return "available", "domain not found"
    upper = response.upper()
    for marker in AVAILABLE_MARKERS:
        if marker in upper:
            return "available", marker
    for marker in THROTTLE_MARKERS:
        if marker in upper:
            return "error", marker
    for pattern in TAKEN_REGEXES:
        if re.search(pattern, response, re.IGNORECASE):
            return "taken", "WHOIS record found"
    if "TERMS OF USE" in upper and "DOMAIN NAME" not in upper:
        return "error", "terms-only response"
    return "error", "ambiguous response"


def is_throttle_reason(reason):
    upper = reason.upper()
    for marker in THROTTLE_MARKERS:
        if marker in upper:
            return True
    for hint in THROTTLE_ERROR_HINTS:
        if hint in upper:
            return True
    return False


def load_checkpoint(path):
    try:
        with open(path, "r") as handle:
            line = handle.readline().strip()
    except FileNotFoundError:
        return None
    if not line:
        return None
    parts = line.split(",", 1)
    try:
        row_idx = int(parts[0])
    except ValueError:
        return None
    return row_idx


def save_checkpoint(path, row_idx, word):
    if not path:
        return
    with open(path, "w") as handle:
        handle.write(f"{row_idx},{word}\n")


def check_domain(
    domain,
    server,
    timeout,
    retries,
    retry_sleep,
    debug,
    mode,
    ipv4,
):
    last_error = ""
    for attempt in range(retries + 1):
        response = ""
        error = ""
        if mode in ("socket", "auto"):
            family = socket.AF_INET if ipv4 else 0
            response, error = query_whois_socket(domain, server, timeout, family)
        if mode in ("netcat", "auto") and not response.strip():
            response, error = query_whois_netcat(domain, server, timeout)

        if response.strip():
            status, reason = classify_response(response)
            if status == "error" and debug:
                head = "\n".join(response.splitlines()[:8])
                print(
                    f"[debug] {domain} response head:\n{head}",
                    file=sys.stderr,
                )
            return status, reason

        last_error = error or "empty response"
        if error and is_throttle_reason(error):
            return "error", error
        if debug:
            print(
                f"[debug] {domain} attempt {attempt + 1}: {last_error}",
                file=sys.stderr,
            )
        if attempt < retries:
            time.sleep(retry_sleep)
    return "error", last_error


def main():
    parser = argparse.ArgumentParser(
        description="Check .ai domain availability using a CSV list of words."
    )
    parser.add_argument("csv_path", help="Path to CSV file with words")
    parser.add_argument(
        "--column",
        help="CSV column name or 0-based index (default: first column)",
    )
    parser.add_argument(
        "--no-header",
        action="store_true",
        help="Treat first row as data even if it looks like a header",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Base seconds to sleep between WHOIS queries (default: 0.5)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retries per domain on empty response or errors (default: 2)",
    )
    parser.add_argument(
        "--retry-sleep",
        type=float,
        default=1.0,
        help="Seconds to sleep between retries (default: 1.0)",
    )
    parser.add_argument(
        "--max-sleep",
        type=float,
        default=10.0,
        help="Max backoff sleep in seconds when throttled (default: 10.0)",
    )
    parser.add_argument(
        "--backoff-factor",
        type=float,
        default=2.0,
        help="Backoff multiplier when throttled (default: 2.0)",
    )
    parser.add_argument(
        "--throttle-retries",
        type=int,
        default=3,
        help="Retries per domain when throttled (default: 3)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print debug info for failed WHOIS queries",
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_WHOIS_SERVER,
        help=f"WHOIS server (default: {DEFAULT_WHOIS_SERVER})",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "socket", "netcat"),
        default="auto",
        help="WHOIS query mode (default: auto)",
    )
    parser.add_argument(
        "--ipv4",
        action="store_true",
        help="Force IPv4 for socket mode",
    )
    parser.add_argument(
        "--output",
        help="Write CSV output to a file (appends when --resume is used)",
    )
    parser.add_argument(
        "--checkpoint",
        default=".whois_checkpoint",
        help="Checkpoint file path (default: .whois_checkpoint)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume after the last checkpoint row",
    )
    args = parser.parse_args()

    last_row_idx = None
    if args.resume and args.checkpoint:
        last_row_idx = load_checkpoint(args.checkpoint)
        if last_row_idx is None and args.debug:
            print(
                f"[debug] checkpoint not found or invalid: {args.checkpoint}",
                file=sys.stderr,
            )

    out_handle = sys.stdout
    close_out = False
    output_exists = args.output and os.path.exists(args.output)
    output_has_data = output_exists and os.path.getsize(args.output) > 0
    if args.output:
        out_mode = "a" if args.resume and output_exists else "w"
        out_handle = open(args.output, out_mode, newline="")
        close_out = True

    writer = csv.writer(out_handle)
    if not (args.output and args.resume and output_has_data):
        writer.writerow(["word", "domain", "status", "reason"])

    cache = {}
    first = True
    current_sleep = args.sleep
    try:
        for row_idx, word in iter_words(args.csv_path, args.column, args.no_header):
            if last_row_idx is not None and row_idx <= last_row_idx:
                continue
            label = word.strip().lower()
            valid, reason = is_valid_label(label)
            domain = f"{label}.ai" if label else ".ai"
            if not valid:
                writer.writerow([word, domain, "error", reason])
                save_checkpoint(args.checkpoint, row_idx, word)
                continue

            if domain in cache:
                status, reason = cache[domain]
            else:
                throttle_attempts = 0
                sleep_before = not first
                while True:
                    if sleep_before and current_sleep > 0:
                        time.sleep(current_sleep)
                    status, reason = check_domain(
                        domain,
                        args.server,
                        args.timeout,
                        args.retries,
                        args.retry_sleep,
                        args.debug,
                        args.mode,
                        args.ipv4,
                    )
                    if status == "error" and is_throttle_reason(reason):
                        throttle_attempts += 1
                        if throttle_attempts > args.throttle_retries:
                            status, reason = "error", "throttled"
                            break
                        current_sleep = min(
                            args.max_sleep,
                            max(current_sleep * args.backoff_factor, args.sleep),
                        )
                        if args.debug:
                            print(
                                f"[debug] throttled {domain}, "
                                f"sleeping {current_sleep}s",
                                file=sys.stderr,
                            )
                        sleep_before = True
                        continue
                    current_sleep = args.sleep
                    break

                if status in ("available", "taken"):
                    cache[domain] = (status, reason)
                first = False
            writer.writerow([word, domain, status, reason])
            save_checkpoint(args.checkpoint, row_idx, word)
    finally:
        if close_out:
            out_handle.close()


if __name__ == "__main__":
    main()
