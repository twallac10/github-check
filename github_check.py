#!/usr/bin/env python3
"""Probe every IP behind GitHub's main hostnames, once or on a loop.

Some GitHub hostnames return the full record set in one answer, others return a
single record that changes per query. To cover both, each round:
  1. queries DNS several times per host (straight to the resolver over UDP, so a
     local cache doesn't hand back the same single record every time),
  2. unions the answers with every IP seen in earlier rounds (kept for --ip-ttl),
  3. tests each IP directly: TCP connect, TLS handshake (SNI + cert verified
     against the hostname) and an HTTP GET with the right Host header.

Usage:
  ./github_check.py                 # loop forever, one round per 60s
  ./github_check.py --once          # single round; exit 1 if anything failed
  ./github_check.py --interval 30 --csv results.csv --ipv6

Stdlib only, Python 3.8+.
"""
import argparse
import csv
import os
import random
import socket
import ssl
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# host -> (path, acceptable status codes)
ENDPOINTS = {
    "github.com": ("/", {200}),
    "api.github.com": ("/rate_limit", {200}),  # exempt from the API rate limit
    "gist.github.com": ("/", {200, 301, 302}),
    "codeload.github.com": ("/", {200, 301, 302, 400, 404}),
    "raw.githubusercontent.com": ("/github/gitignore/main/README.md", {200}),
    "avatars.githubusercontent.com": ("/u/1?s=40", {200}),
    "objects.githubusercontent.com": ("/", {200, 301, 302, 400, 404}),
    "camo.githubusercontent.com": ("/", {200, 301, 302, 400, 404}),
    "github.githubassets.com": ("/favicons/favicon.svg", {200}),
}

QTYPES = {"A": 1, "AAAA": 28}
CSV_FIELDS = ["ts", "host", "ip", "family", "fresh", "ok", "status",
              "connect_ms", "tls_ms", "ttfb_ms", "total_ms", "error"]


# ---------------------------------------------------------------- DNS

def system_nameservers():
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                    servers.append(parts[1])
    except OSError:
        pass
    return servers or ["8.8.8.8"]


def _skip_name(buf, off):
    while True:
        n = buf[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:
            return off + 2
        off += 1 + n


class DNSError(Exception):
    """Unusable DNS answer (error rcode, not a response, etc.); try the next server."""


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise DNSError("TCP connection closed mid-answer")
        buf += chunk
    return buf


def dns_query(host, qtype, server, timeout=2.0):
    """Return the A/AAAA addresses in one DNS answer (CNAMEs are skipped).

    Asks over UDP; if the answer comes back truncated (TC bit) it is re-asked
    over TCP so a large record set isn't silently cut short.
    """
    txid = random.randrange(65536)
    q = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in host.rstrip(".").split(".")) + b"\0"
    q += struct.pack(">HH", QTYPES[qtype], 1)
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    deadline = time.monotonic() + timeout
    with socket.socket(fam, socket.SOCK_DGRAM) as s:
        s.connect((server, 53))  # kernel then drops datagrams from other sources
        s.send(q)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("DNS query timed out")
            s.settimeout(remaining)
            data = s.recv(4096)
            if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == txid:
                break
    if struct.unpack(">H", data[2:4])[0] & 0x0200:  # TC: truncated, retry over TCP
        with socket.socket(fam, socket.SOCK_STREAM) as s:
            s.settimeout(max(0.1, deadline - time.monotonic()) + timeout)
            s.connect((server, 53))
            s.sendall(struct.pack(">H", len(q)) + q)
            data = _recv_exact(s, struct.unpack(">H", _recv_exact(s, 2))[0])
        if len(data) < 12 or struct.unpack(">H", data[:2])[0] != txid:
            raise DNSError("bad TCP answer")
    flags = struct.unpack(">H", data[2:4])[0]
    if not flags & 0x8000:
        raise DNSError("not a response")
    if flags & 0x000F:  # SERVFAIL/REFUSED/NXDOMAIN/...: let another server or the OS resolver try
        raise DNSError(f"rcode {flags & 0x000F}")
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == QTYPES["A"] and rdlen == 4:
            ips.append(socket.inet_ntop(socket.AF_INET, data[off:off + 4]))
        elif rtype == QTYPES["AAAA"] and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, data[off:off + 16]))
        off += rdlen
    return ips


def resolve(host, qtypes, queries, delay, servers):
    """Query repeatedly; return (union of every address seen, used OS-resolver fallback).

    Never raises: a host whose DNS fails entirely just yields an empty set.
    """
    seen = set()
    raw_dead = set()  # qtypes for which no raw server answered this round
    fallback = False
    for i in range(queries):
        for qt in qtypes:
            got = False
            if qt not in raw_dead:
                for server in servers:
                    try:
                        seen.update(dns_query(host, qt, server))
                        got = True
                        break
                    except (OSError, DNSError, struct.error, IndexError, ValueError):
                        continue
                if not got:
                    # Don't burn (servers x timeout) on every remaining query this round.
                    raw_dead.add(qt)
            if not got:  # raw DNS blocked (e.g. proxy/sandbox): use the OS resolver
                fallback = True
                fam = socket.AF_INET if qt == "A" else socket.AF_INET6
                try:
                    seen.update(ai[4][0] for ai in socket.getaddrinfo(host, 443, fam, socket.SOCK_STREAM))
                except (OSError, UnicodeError):
                    pass
        if i < queries - 1:
            time.sleep(delay)
    return seen, fallback


# ---------------------------------------------------------------- probe

def probe(host, ip, path, ok_status, timeout, ctx):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    res = {"host": host, "ip": ip, "family": "v6" if fam == socket.AF_INET6 else "v4",
           "ok": False, "status": "", "connect_ms": "", "tls_ms": "", "ttfb_ms": "",
           "total_ms": "", "error": ""}
    t0 = time.perf_counter()
    sock = None
    phase = "connect"
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        t1 = time.perf_counter()
        res["connect_ms"] = round((t1 - t0) * 1000, 1)
        phase = "tls"
        sock = ctx.wrap_socket(sock, server_hostname=host)
        t2 = time.perf_counter()
        res["tls_ms"] = round((t2 - t1) * 1000, 1)
        phase = "http"
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      "User-Agent: github-check/1.0\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n").encode())
        buf = b""
        # Cap the read so a misbehaving peer can't keep us here indefinitely.
        while b"\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        t3 = time.perf_counter()
        res["ttfb_ms"] = round((t3 - t2) * 1000, 1)
        parts = buf.split(b"\r\n", 1)[0].split()
        if len(parts) >= 2 and parts[0].startswith(b"HTTP/") and parts[1].isdigit():
            res["status"] = int(parts[1])
            res["ok"] = res["status"] in ok_status
            if not res["ok"]:
                res["error"] = f"unexpected status {res['status']}"
        else:
            res["error"] = ("http: connection closed before response" if not buf
                            else "http: bad HTTP response")
    except ssl.SSLCertVerificationError as e:
        res["error"] = f"cert: {e.verify_message}"
    except ssl.SSLError as e:
        res["error"] = f"{phase}: {e.reason or e}"
    except socket.timeout:
        res["error"] = f"{phase}: timeout"
    except OSError as e:
        res["error"] = f"{phase}: {type(e).__name__}: {e.strerror or e}"
    except Exception as e:  # never let one IP take down the round
        res["error"] = f"{phase}: {type(e).__name__}: {e}"
    finally:
        res["total_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return res


# ---------------------------------------------------------------- rounds

def run_round(args, known, servers, csv_writer):
    """known: {host: {ip: last_seen_epoch}}, mutated in place."""
    now = time.time()
    qtypes = ["A", "AAAA"] if args.ipv6 else ["A"]
    hosts = args.hosts

    with ThreadPoolExecutor(max_workers=len(hosts)) as ex:
        resolved = dict(zip(hosts, ex.map(
            lambda h: resolve(h, qtypes, args.dns_queries, args.dns_delay, servers), hosts)))
    dns = {h: ips for h, (ips, _) in resolved.items()}
    fallback = {h: fb for h, (_, fb) in resolved.items()}

    jobs = []
    for h in hosts:
        for ip in dns[h]:
            known[h][ip] = now
        for ip in [i for i, seen in known[h].items() if now - seen > args.ip_ttl]:
            del known[h][ip]
        for ip in sorted(known[h], key=lambda x: (":" in x, socket.inet_pton(
                socket.AF_INET6 if ":" in x else socket.AF_INET, x))):
            jobs.append((h, ip, ip in dns[h]))

    ctx = ssl.create_default_context()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(
            lambda j: dict(probe(j[0], j[1], ENDPOINTS[j[0]][0], ENDPOINTS[j[0]][1],
                                 args.timeout, ctx), fresh=j[2]), jobs))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n=== {ts}  {len(results)} IPs across {len(hosts)} hosts "
          f"(resolvers: {', '.join(servers)}) ===")
    failures = 0
    no_addr = []
    for h in hosts:
        rs = [r for r in results if r["host"] == h]
        bad = [r for r in rs if not r["ok"]]
        failures += len(bad)
        note = f"{len(dns[h])} from DNS this round"
        if fallback[h]:
            note += ", via system resolver (raw DNS failed)"
        print(f"{h}: {len(rs) - len(bad)}/{len(rs)} ok  ({note})")
        for r in rs:
            if r["ok"] and args.quiet:
                continue
            mark = "ok  " if r["ok"] else "FAIL"
            new = "" if r["fresh"] else " (not in this round's DNS)"
            ms = {k: "-" if r[k] == "" else r[k] for k in ("connect_ms", "tls_ms", "ttfb_ms")}
            print(f"  {mark} {r['ip']:<40} {str(r['status']):>3}  "
                  f"conn {ms['connect_ms']:>6}  tls {ms['tls_ms']:>6}  "
                  f"ttfb {ms['ttfb_ms']:>6} ms  {r['error']}{new}")
        if not rs:
            print("  FAIL no addresses resolved")
            failures += 1
            no_addr.append({"host": h, "ip": "", "family": "", "fresh": False, "ok": False,
                            "status": "", "connect_ms": "", "tls_ms": "", "ttfb_ms": "",
                            "total_ms": "", "error": "no addresses resolved"})
    if csv_writer:
        for r in results + no_addr:  # no_addr rows so DNS outages show up in the CSV too
            csv_writer.writerow({"ts": ts, **{k: r[k] for k in CSV_FIELDS if k != "ts"}})
    print(f"round result: {'ALL OK' if not failures else f'{failures} FAILURE(S)'}", flush=True)
    return failures


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interval", type=float, default=60, help="seconds between round starts (default 60)")
    p.add_argument("--once", action="store_true", help="run one round and exit (exit 1 on any failure)")
    p.add_argument("--hosts", nargs="+", default=list(ENDPOINTS), help="hostnames to test (default: all built in)")
    p.add_argument("--dns-queries", type=int, default=8, help="DNS queries per host per round (default 8)")
    p.add_argument("--dns-delay", type=float, default=0.3, help="seconds between those queries (default 0.3)")
    p.add_argument("--ip-ttl", type=float, default=3600,
                   help="keep testing an IP this many seconds after DNS last returned it (default 3600)")
    p.add_argument("--resolver", action="append",
                   help="DNS server IP (repeatable; default IPv4 servers from /etc/resolv.conf)")
    p.add_argument("--ipv6", action="store_true", help="also resolve and test AAAA records")
    p.add_argument("--timeout", type=float, default=5, help="per-IP connect/read timeout (default 5)")
    p.add_argument("--workers", type=int, default=32, help="parallel probes (default 32)")
    p.add_argument("--csv", help="append every result to this CSV file")
    p.add_argument("--quiet", action="store_true", help="only print failing IPs")
    args = p.parse_args()

    args.hosts = list(dict.fromkeys(h.lower().rstrip(".") for h in args.hosts))  # dedupe, keep order
    unknown = [h for h in args.hosts if h not in ENDPOINTS]
    if unknown:
        p.error(f"no probe path defined for: {', '.join(unknown)} (add it to ENDPOINTS)")
    if args.dns_queries < 1 or args.workers < 1:
        p.error("--dns-queries and --workers must be at least 1")
    if args.timeout <= 0 or args.interval < 0 or args.dns_delay < 0 or args.ip_ttl < 0:
        p.error("--timeout must be > 0; --interval, --dns-delay and --ip-ttl must be >= 0")
    for r in args.resolver or []:
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in r else socket.AF_INET, r)
        except OSError:
            p.error(f"--resolver must be an IP address: {r}")

    servers = args.resolver or system_nameservers()
    known = {h: {} for h in args.hosts}

    csv_file = csv_writer = None
    if args.csv:
        try:
            new = not os.path.exists(args.csv) or os.path.getsize(args.csv) == 0
            csv_file = open(args.csv, "a", newline="")
        except OSError as e:
            p.error(f"cannot open --csv file: {e}")
        csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDS)
        if new:
            csv_writer.writeheader()

    try:
        next_start = time.monotonic()
        while True:
            try:
                failures = run_round(args, known, servers, csv_writer)
                if csv_file:
                    csv_file.flush()
            except Exception as e:  # a broken round must never kill the loop
                print(f"\nround error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
                failures = 1
            if args.once:
                return 1 if failures else 0
            # Fixed schedule (no cumulative drift); if a round overran, start the next now.
            next_start += args.interval
            now = time.monotonic()
            if next_start < now:
                next_start = now
            time.sleep(next_start - now)
    except KeyboardInterrupt:
        print("\nstopped")
        return 0
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    sys.exit(main())
