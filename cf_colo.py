#!/usr/bin/env python3
"""Track which Cloudflare colo (data centre) your traffic lands in, once or on a loop.

Each round, for every Cloudflare-proxied hostname:
  1. resolves it (reusing github_check.resolve, which queries DNS repeatedly so
     rotating answers are all collected) or uses a pinned IP from --pin,
  2. opens --samples fresh TLS connections to each edge IP (SNI + cert verified) and
     requests /cdn-cgi/trace, which reports colo=XXX, your public ip=, loc=, http=, tls=, warp=,
  3. cross-checks the colo against the suffix of the CF-RAY response header,
  4. records every colo change (and every outage/recovery) per host/IP.

For overnight runs, --events writes one durable row per change/outage, --csv writes every
sample, and a summary (colo share, switch count and rate, time in current colo, switches
per hour) is printed every --summary-every seconds and on exit (Ctrl-C or SIGTERM).

Usage:
  ./cf_colo.py                              # loop forever, one round per 60s
  ./cf_colo.py --once
  ./cf_colo.py --quiet --csv samples.csv --events events.csv --interval 30 --samples 3
  ./cf_colo.py --pin www.cloudflare.com=104.16.124.96

Stdlib only, Python 3.8+. Needs github_check.py alongside it.
"""
import argparse
import csv
import os
import signal
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
EVENT_FIELDS = ["ts", "type", "host", "ip", "from_colo", "to_colo", "duration_s"]


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_dur(secs):
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else (f"{m}m{s:02d}s" if m else f"{s}s")


# ---------------------------------------------------------------- probing

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
        for field, key in (("colo", "colo"), ("loc", "loc"), ("client_ip", "ip"),
                           ("http", "http"), ("tls", "tls"), ("warp", "warp")):
            res[field] = kv.get(key, "")
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


def fetch_samples(host, ip, samples, gap, timeout, ctx):
    """Several fresh connections (new source port each) so per-flow routing differences show up."""
    out = []
    for i in range(samples):
        if i:
            time.sleep(gap)
        out.append(fetch_trace(host, ip, timeout, ctx))
    return out


# ---------------------------------------------------------------- tracking

class Stats:
    """Per host/IP history. Failed samples never reset the 'current colo'."""

    def __init__(self):
        self.obs = 0
        self.fails = 0
        self.colos = Counter()
        self.switches = 0
        self.last = None       # colo currently serving this IP
        self.since = None      # epoch when it was first seen serving it
        self.failing = False
        self.fail_since = None
        self.longest = {}      # colo -> longest unbroken stay (s)

    def record(self, now, ok, colo):
        """Returns [(type, from_colo, to_colo, duration_s)] for anything noteworthy."""
        events = []
        self.obs += 1
        if not ok:
            self.fails += 1
            if not self.failing:
                self.failing, self.fail_since = True, now
                events.append(("fail_start", "", "", 0))
            return events
        if self.failing:
            events.append(("recovered", "", colo, now - self.fail_since))
            self.failing = False
        self.colos[colo] += 1
        if self.last is None:
            self.last, self.since = colo, now
        elif colo != self.last:
            dwell = now - self.since
            self.longest[self.last] = max(self.longest.get(self.last, 0), dwell)
            events.append(("colo_change", self.last, colo, dwell))
            self.switches += 1
            self.last, self.since = colo, now
        return events


def print_summary(stats, hourly, started):
    now = time.time()
    elapsed = now - started
    print(f"\n--- summary: {fmt_dur(elapsed)} running, since {utc(started)} ---")
    for (host, ip), s in sorted(stats.items()):
        good = s.obs - s.fails
        share = ", ".join(f"{c} {n / good * 100:.1f}%" for c, n in s.colos.most_common()) \
            if good else "no successful samples"
        rate = s.switches / (elapsed / 3600) if elapsed > 0 else 0
        current = f" | now {s.last} for {fmt_dur(now - s.since)}" if s.last else ""
        longest = ""
        if s.longest or s.last:
            best = dict(s.longest)
            if s.last:
                best[s.last] = max(best.get(s.last, 0), now - s.since)
            longest = " | longest stay " + ", ".join(f"{c} {fmt_dur(d)}" for c, d in
                                                      sorted(best.items(), key=lambda x: -x[1]))
        print(f"{host} {ip}: {s.obs} samples, {s.fails} failed | {share} | "
              f"{s.switches} switches ({rate:.2f}/h){current}{longest}")
    if hourly:
        print("switches by hour (local): " + ", ".join(f"{h} x{n}" for h, n in sorted(hourly.items())))
    sys.stdout.flush()


# ---------------------------------------------------------------- rounds

def run_round(args, servers, stats, hourly, csv_writer, event_writer):
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
        sampled = list(ex.map(lambda j: fetch_samples(j[0], j[1], args.samples, args.sample_gap,
                                                      args.timeout, ctx), jobs))

    now = time.time()
    ts = utc(now)
    if not args.quiet:
        n = sum(len(s) for s in sampled)
        print(f"\n=== {ts}  {len(jobs)} edge IPs across {len(hosts)} hosts, {n} samples ===")
    failures = 0
    noteworthy = False
    for h in hosts:
        rows = [(ip, rs) for (hh, ip), rs in zip(jobs, sampled) if hh == h]
        if not args.quiet:
            print(f"{h}: {len(rows)} IP(s)")
        if not rows:
            failures += 1
            noteworthy = True
            print(f"{'' if args.quiet else '  '}{h}: no addresses resolved (round {ts})")
            if event_writer:
                event_writer.writerow({"ts": ts, "type": "no_addresses", "host": h})
        for ip, rs in rows:
            st = stats.setdefault((h, ip), Stats())
            for r in rs:
                evs = st.record(now, r["ok"], r["colo"])
                r["changed"] = any(e[0] == "colo_change" for e in evs)
                if not r["ok"]:
                    failures += 1
                for typ, frm, to, dur in evs:
                    noteworthy = True
                    if typ == "colo_change":
                        hourly[datetime.now().strftime("%m-%d %H:00")] += 1
                    msg = {"colo_change": f"CHANGED {frm} -> {to} after {fmt_dur(dur)}",
                           "fail_start": f"FAILING: {r['error']}",
                           "recovered": f"RECOVERED (colo {to}) after {fmt_dur(dur)} down"}[typ]
                    if args.quiet:
                        print(f"{ts} {h} {ip}: {msg}")
                    if event_writer:
                        event_writer.writerow({"ts": ts, "type": typ, "host": h, "ip": ip,
                                               "from_colo": frm, "to_colo": to,
                                               "duration_s": round(dur)})
                if csv_writer:
                    csv_writer.writerow({"ts": ts, **{k: r.get(k, "") for k in CSV_FIELDS if k != "ts"}})
            if args.quiet:
                continue
            for r in rs:
                if r["ok"]:
                    note = ""
                    if r["changed"]:
                        note += f"  CHANGED to {r['colo']}"
                    if r["ray_colo"] and r["ray_colo"] != r["colo"]:
                        note += f"  (CF-RAY says {r['ray_colo']})"
                    print(f"  ok   {ip:<40} colo {r['colo']:<4} loc {r['loc']:<3} "
                          f"{r['total_ms']:>6} ms  via {r['client_ip']}{note}")
                else:
                    print(f"  FAIL {ip:<40} {r['error']}")
    if not args.quiet:
        print(f"round result: {'ALL OK' if not failures else f'{failures} FAILURE(S)'}")
    if csv_writer and not jobs:
        csv_writer.writerow({"ts": ts, "ok": False, "error": "no addresses resolved"})
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


def open_csv(path, fields, parser, flag):
    try:
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        f = open(path, "a", newline="")
    except OSError as e:
        parser.error(f"cannot open {flag} file: {e}")
    w = csv.DictWriter(f, fieldnames=fields)
    if new:
        w.writeheader()
        f.flush()
    return f, w


def _terminate(signum, frame):
    raise KeyboardInterrupt


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--interval", type=float, default=60, help="seconds between round starts (default 60)")
    p.add_argument("--once", action="store_true", help="run one round and exit (exit 1 on any failure)")
    p.add_argument("--hosts", nargs="+", default=DEFAULT_HOSTS,
                   help="Cloudflare-proxied hostnames to test (default: %s)" % " ".join(DEFAULT_HOSTS))
    p.add_argument("--pin", action="append", metavar="HOST=IP",
                   help="skip DNS for HOST and test this edge IP instead (repeatable)")
    p.add_argument("--samples", type=int, default=1,
                   help="fresh connections per IP per round; >1 catches flows split across colos (default 1)")
    p.add_argument("--sample-gap", type=float, default=0.2, help="seconds between those samples (default 0.2)")
    p.add_argument("--dns-queries", type=int, default=3, help="DNS queries per host per round (default 3)")
    p.add_argument("--dns-delay", type=float, default=0.3, help="seconds between those queries (default 0.3)")
    p.add_argument("--resolver", action="append", help="DNS server IP (repeatable; default /etc/resolv.conf)")
    p.add_argument("--ipv6", action="store_true", help="also resolve and test AAAA records")
    p.add_argument("--timeout", type=float, default=5, help="per-IP connect/read timeout (default 5)")
    p.add_argument("--workers", type=int, default=16, help="parallel probes (default 16)")
    p.add_argument("--csv", help="append every sample to this CSV file")
    p.add_argument("--events", help="append one row per colo change / outage / recovery to this CSV file")
    p.add_argument("--summary-every", type=float, default=3600,
                   help="print a summary this often, in seconds; 0 = only on exit (default 3600)")
    p.add_argument("--quiet", action="store_true",
                   help="print only colo changes, outages and the periodic summary (use for overnight runs)")
    args = p.parse_args()

    if args.interval < 0 or args.dns_delay < 0 or args.sample_gap < 0 or args.summary_every < 0:
        p.error("--interval, --dns-delay, --sample-gap and --summary-every must be >= 0")
    if args.dns_queries < 1 or args.workers < 1 or args.samples < 1 or args.timeout <= 0:
        p.error("--dns-queries, --workers and --samples must be >= 1, --timeout > 0")
    args.hosts = list(dict.fromkeys(h.lower() for h in args.hosts))
    args.pins = parse_pins(args.pin, p)
    servers = args.resolver or system_nameservers()

    files = []
    csv_writer = event_writer = None
    if args.csv:
        f, csv_writer = open_csv(args.csv, CSV_FIELDS, p, "--csv")
        files.append(f)
    if args.events:
        f, event_writer = open_csv(args.events, EVENT_FIELDS, p, "--events")
        files.append(f)

    signal.signal(signal.SIGTERM, _terminate)
    stats, hourly = {}, Counter()
    started = time.time()
    last_summary = time.monotonic()
    code = 0
    try:
        next_start = time.monotonic()
        while True:
            try:
                code = 1 if run_round(args, servers, stats, hourly, csv_writer, event_writer) else 0
            except Exception as e:  # a bad round must not end an overnight run
                print(f"{utc(time.time())} round failed: {type(e).__name__}: {e}", file=sys.stderr)
                code = 1
            for f in files:
                try:
                    f.flush()
                except OSError as e:
                    print(f"cannot write {f.name}: {e}", file=sys.stderr)
            if args.once:
                if not args.quiet:
                    print_summary(stats, hourly, started)
                return code
            if args.summary_every and time.monotonic() - last_summary >= args.summary_every:
                print_summary(stats, hourly, started)
                last_summary = time.monotonic()
            next_start += args.interval
            if next_start < time.monotonic():  # overran or machine slept: don't burst to catch up
                next_start = time.monotonic()
            time.sleep(max(0, next_start - time.monotonic()))
    except KeyboardInterrupt:
        print("\nstopped.")
        print_summary(stats, hourly, started)
        return 0
    finally:
        for f in files:
            f.close()


if __name__ == "__main__":
    sys.exit(main())
