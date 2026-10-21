#!/usr/bin/env python3
"""Track which Cloudflare colo (data centre) your traffic lands in, once or on a loop.

Each round, for every Cloudflare-proxied hostname:
  1. resolves it (reusing github_check.resolve, which queries DNS repeatedly so
     rotating answers are all collected) or uses a pinned IP from --pin,
  2. connects to each edge IP over TLS (SNI + cert verified) and requests
     /cdn-cgi/trace, which reports colo=XXX, your public ip=, loc=, http=, tls=, warp=,
  3. cross-checks the colo against the suffix of the CF-RAY response header,
  4. reports whenever the colo for a host/IP changes from the previous round.

Usage:
  ./cf_colo.py                              # loop forever, one round per 60s
  ./cf_colo.py --once
  ./cf_colo.py --csv colo.csv --pin www.cloudflare.com=104.16.124.96

Stdlib only, Python 3.8+. Needs github_check.py alongside it.
"""
import argparse
import csv
import os
import socket
import ssl
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from github_check import resolve, system_nameservers

DEFAULT_HOSTS = ["www.cloudflare.com", "one.one.one.one"]
CSV_FIELDS = ["ts", "host", "ip", "ok", "colo", "ray_colo", "loc", "client_ip",
              "http", "tls", "warp", "changed", "total_ms", "error"]


def fetch_trace(host, ip, timeout, ctx):
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    res = {"host": host, "ip": ip, "ok": False, "colo": "", "ray_colo": "", "loc": "",
           "client_ip": "", "http": "", "tls": "", "warp": "", "total_ms": "", "error": ""}
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.socket(fam, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 443))
        sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall((f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
                      "User-Agent: cf-colo/1.0\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n").encode())
        buf = b""
        while len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = lines[0].split()
        if len(status) < 2 or not status[0].startswith("HTTP/") or status[1] != "200":
            res["error"] = f"http: {lines[0][:60] or 'no response'}"
            return res
        for line in lines[1:]:
            k, _, v = line.partition(":")
            if k.strip().lower() == "cf-ray" and "-" in v:
                res["ray_colo"] = v.strip().rsplit("-", 1)[1]
        kv = dict(l.split("=", 1) for l in body.decode("utf-8", "replace").splitlines() if "=" in l)
        res["colo"] = kv.get("colo", "")
        res["loc"] = kv.get("loc", "")
        res["client_ip"] = kv.get("ip", "")
        res["http"] = kv.get("http", "")
        res["tls"] = kv.get("tls", "")
        res["warp"] = kv.get("warp", "")
        if not res["colo"]:
            res["error"] = "no colo in trace (is this host proxied by Cloudflare?)"
        else:
            res["ok"] = True
    except ssl.SSLCertVerificationError as e:
        res["error"] = f"cert: {e.verify_message}"
    except ssl.SSLError as e:
        res["error"] = f"tls: {e.reason or e}"
    except socket.timeout:
        res["error"] = "timeout"
    except Exception as e:  # never let one probe kill the round
        res["error"] = f"{type(e).__name__}: {getattr(e, 'strerror', None) or e}"
    finally:
        res["total_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        if sock:
            try:
                sock.close()
            except OSError:
                pass
    return res


def run_round(args, servers, last, counts, csv_writer):
    """last: {(host, ip): colo}; counts: {host: Counter of colos}; both mutated."""
    qtypes = ["A", "AAAA"] if args.ipv6 else ["A"]
    hosts = args.hosts

    def addrs(h):
        if h in args.pins:
            return args.pins[h]
        return sorted(resolve(h, qtypes, args.dns_queries, args.dns_delay, servers)[0],
                      key=lambda x: (":" in x, x))

    with ThreadPoolExecutor(max_workers=len(hosts)) as ex:
        ips = dict(zip(hosts, ex.map(addrs, hosts)))
    jobs = [(h, ip) for h in hosts for ip in ips[h]]

    ctx = ssl.create_default_context()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda j: fetch_trace(j[0], j[1], args.timeout, ctx), jobs))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"\n=== {ts}  {len(results)} edge IPs across {len(hosts)} hosts ===")
    failures = 0
    for h in hosts:
        rs = [r for r in results if r["host"] == h]
        print(f"{h}: {len(rs)} IP(s)")
        if not rs:
            print("  no addresses resolved")
            failures += 1
        for r in rs:
            key = (h, r["ip"])
            prev = last.get(key)
            r["changed"] = bool(r["ok"] and prev and prev != r["colo"])
            if r["ok"]:
                last[key] = r["colo"]
                counts[h][r["colo"]] += 1
                note = f"  CHANGED {prev} -> {r['colo']}" if r["changed"] else ""
                if r["ray_colo"] and r["ray_colo"] != r["colo"]:
                    note += f"  (CF-RAY says {r['ray_colo']})"
                if not (args.quiet and not note):
                    print(f"  ok   {r['ip']:<40} colo {r['colo']:<4} loc {r['loc']:<3} "
                          f"{r['total_ms']:>6} ms  via {r['client_ip']}{note}")
            else:
                failures += 1
                print(f"  FAIL {r['ip']:<40} {r['error']}")
    if csv_writer:
        if not results:
            csv_writer.writerow({"ts": ts, "ok": False, "error": "no addresses resolved"})
        for r in results:
            csv_writer.writerow({"ts": ts, **{k: r.get(k, "") for k in CSV_FIELDS if k != "ts"}})
    print(f"round result: {'ALL OK' if not failures else f'{failures} FAILURE(S)'}")
    sys.stdout.flush()
    return failures


def parse_pins(values, parser):
    pins = {}
    for v in values or []:
        host, sep, ip = v.partition("=")
        if not sep or not host or not ip:
            parser.error(f"--pin expects HOST=IP, got {v!r}")
        try:
            socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        except OSError:
            parser.error(f"--pin: {ip!r} is not an IP address")
        pins.setdefault(host.lower(), []).append(ip)
    return pins


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interval", type=float, default=60, help="seconds between round starts (default 60)")
    p.add_argument("--once", action="store_true", help="run one round and exit (exit 1 on any failure)")
    p.add_argument("--hosts", nargs="+", default=DEFAULT_HOSTS,
                   help="Cloudflare-proxied hostnames to test (default: %s)" % " ".join(DEFAULT_HOSTS))
    p.add_argument("--pin", action="append", metavar="HOST=IP",
                   help="skip DNS for HOST and test this edge IP instead (repeatable)")
    p.add_argument("--dns-queries", type=int, default=3, help="DNS queries per host per round (default 3)")
    p.add_argument("--dns-delay", type=float, default=0.3, help="seconds between those queries (default 0.3)")
    p.add_argument("--resolver", action="append", help="DNS server IP (repeatable; default /etc/resolv.conf)")
    p.add_argument("--ipv6", action="store_true", help="also resolve and test AAAA records")
    p.add_argument("--timeout", type=float, default=5, help="per-IP connect/read timeout (default 5)")
    p.add_argument("--workers", type=int, default=16, help="parallel probes (default 16)")
    p.add_argument("--csv", help="append every result to this CSV file")
    p.add_argument("--quiet", action="store_true", help="only print failures and colo changes")
    args = p.parse_args()

    if args.interval < 0 or args.dns_delay < 0:
        p.error("--interval and --dns-delay must be >= 0")
    if args.dns_queries < 1 or args.workers < 1 or args.timeout <= 0:
        p.error("--dns-queries and --workers must be >= 1, --timeout > 0")
    args.hosts = list(dict.fromkeys(h.lower() for h in args.hosts))
    args.pins = parse_pins(args.pin, p)
    servers = args.resolver or system_nameservers()

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

    last = {}
    counts = {h: Counter() for h in args.hosts}
    code = 0
    try:
        next_start = time.monotonic()
        while True:
            try:
                code = 1 if run_round(args, servers, last, counts, csv_writer) else 0
                if csv_file:
                    csv_file.flush()
            except Exception as e:  # a bad round must not end the loop
                print(f"round failed: {type(e).__name__}: {e}", file=sys.stderr)
                code = 1
            if args.once:
                return code
            next_start += args.interval
            time.sleep(max(0, next_start - time.monotonic()))
    except KeyboardInterrupt:
        print("\nstopped. colo sightings per host:")
        for h, c in counts.items():
            print(f"  {h}: " + (", ".join(f"{k} x{v}" for k, v in c.most_common()) or "none"))
        return 0
    finally:
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    sys.exit(main())
