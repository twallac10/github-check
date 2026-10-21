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
Tracks which Cloudflare colo (data centre) your traffic lands in. Each round it resolves Cloudflare-proxied hostnames (default `www.cloudflare.com`, `one.one.one.one`), connects to every edge IP over TLS, reads `/cdn-cgi/trace` (`colo=`, `loc=`, your public `ip=`, `http=`, `tls=`, `warp=`), cross-checks the `CF-RAY` header, and flags when the colo for a host/IP changes. Ctrl-C prints a summary of colo sightings. It imports the DNS code from `github_check.py`, so keep the two files together.

```
./cf_colo.py                                       # loop forever, one round per 60s
./cf_colo.py --once
./cf_colo.py --csv colo.csv --quiet                # --quiet: only failures and colo changes
./cf_colo.py --pin www.cloudflare.com=104.16.124.96  # test a specific edge IP, skipping DNS
```

It shows where your traffic enters Cloudflare, not the path onward. Run it from different networks or VPNs to see different colos.
