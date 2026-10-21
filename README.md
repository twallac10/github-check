# github-check
Script to check the availability of the GitHub IP's

`github_check.py` probes every IP behind GitHub's main hostnames (github.com, api, gist, codeload, raw/avatars/objects/camo.githubusercontent.com, github.githubassets.com).

Some GitHub DNS names return the full record set in one answer, others return a single record that changes per query. Each round it queries DNS several times per host, merges the answers with IPs seen earlier (kept for `--ip-ttl`), then tests every IP directly: TCP connect, TLS (SNI + certificate check) and an HTTP GET with the right `Host` header.

Python 3.8+, standard library only.

```
./github_check.py                       # loop forever, one round per 60s
./github_check.py --once                # single round; exit 1 if anything failed
./github_check.py --csv results.csv --quiet --ipv6
```

Run `./github_check.py --help` for all options.

## cf_colo.py
Tracks which Cloudflare colo (data centre) your traffic lands in. Each round it resolves Cloudflare-proxied hostnames (default `www.cloudflare.com`, `one.one.one.one`), opens fresh TLS connections to every edge IP, reads `/cdn-cgi/trace` (`colo=`, `loc=`, your public `ip=`, `http=`, `tls=`, `warp=`) and cross-checks the `CF-RAY` header. It imports the DNS code from `github_check.py`, so keep the two files together.

Built for overnight runs, to see how often the colo switches:

```
./cf_colo.py --quiet --interval 30 --samples 3 --csv samples.csv --events events.csv
```

- `--quiet` prints only colo changes, outages and a periodic summary (`--summary-every`, default 1h).
- `--events` writes one row per colo change, outage start and recovery (with how long the previous colo/outage lasted). This is the file to analyse in the morning.
- `--csv` writes every sample.
- `--samples N` opens N fresh connections per IP each round, which catches flows that get split across colos.
- On Ctrl-C or SIGTERM it prints a summary: share of samples per colo, switch count and rate per hour, time in the current colo, longest stay per colo, and switches by hour.
- A failed probe never counts as a switch, and a machine sleeping doesn't cause a burst of catch-up rounds.

Other options: `--once`, `--pin HOST=IP` (test a specific edge IP, skipping DNS), `--hosts`, `--ipv6`, `--resolver`. See `./cf_colo.py --help`.

It shows where your traffic enters Cloudflare, not the path onward. Run it from different networks or VPNs to see different colos.
