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
