#!/usr/bin/env python3
"""Build blocklist.txt from the sources in CollectionOfBlockingUrls.txt.

Security notes:
- Downloaded lists are untrusted text: they are only parsed, never executed.
- HTTPS only, per-source size cap and timeout.
- Stdlib only (no third-party dependencies).
- Guard rails abort the run (non-zero exit) when too many sources fail or the
  domain count swings too much, so a broken or poisoned upstream cannot
  silently wipe or flood the list.

Usage: python3 -I scripts/build_blocklist.py [--sources FILE] [--output FILE] [--report FILE]
"""
import argparse
import datetime
import re
import sys
import urllib.error
import urllib.request

MAX_BYTES = 100 * 1024 * 1024        # per-source download cap (100 MiB)
TIMEOUT = 60                         # seconds per request
MIN_SOURCE_SUCCESS = 0.80            # abort if fewer than 80 % of sources download
MAX_CHANGE = 0.25                    # abort if domain count changes more than ±25 %
USER_AGENT = 'pi-hole-blocklist-builder (+https://github.com/Silassentinel/Pi-Hole-blocklist)'

LABEL = re.compile(r'^(?!-)[a-z0-9_-]{1,63}(?<!-)$')        # underscores allowed: real tracker hostnames use them
TLD = re.compile(r'^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$')   # alphabetic or punycode TLD (rejects bare IPs)
HOSTS_IP = {'0.0.0.0', '127.0.0.1', '::', '::1', '::0'}
RESERVED = {'localhost', 'localhost.localdomain', 'local', 'broadcasthost', 'ip6-localhost', 'ip6-loopback'}
ABP = re.compile(r'^\|\|?([^/^$*|]+)\^?$|^([^/^$*|@#]+)\^$')  # ||d^ / |d / d^ without modifiers


def valid(domain):
    if len(domain) > 253 or '.' not in domain or domain in RESERVED:
        return False
    labels = domain.split('.')
    return all(LABEL.match(l) for l in labels) and TLD.match(labels[-1]) is not None


def parse(text):
    """Yield bare domains from hosts, plain-domain or simple Adblock-style lines; skip everything else."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in '#![':                     # blank, comment, [Adblock Plus] header
            continue
        if re.search(r'#[@?$%]?#', line):                     # cosmetic rules
            continue
        line = re.sub(r'\s+#.*$', '', line)                   # inline "# comment"
        parts = line.split()
        if parts[0] in HOSTS_IP:                              # hosts-file format
            candidates = parts[1:]
        elif len(parts) > 1:
            continue
        else:
            m = ABP.match(parts[0])
            if m:
                candidates = [m.group(1) or m.group(2)]
            elif re.search(r'[/^$*|@?=]', parts[0]):          # URL/path rules or rules with modifiers
                continue
            else:
                candidates = parts
        for c in candidates:
            d = c.lower().rstrip('.')
            if valid(d):
                yield d


def fetch(url):
    if not url.startswith('https://'):
        raise ValueError('non-HTTPS URL refused')
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f'larger than {MAX_BYTES} bytes')
    return data.decode('utf-8', errors='replace')


def previous_domains(path):
    try:
        with open(path, encoding='utf-8') as fh:
            return {l.strip() for l in fh if l.strip() and not l.startswith('#')}
    except FileNotFoundError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sources', default='CollectionOfBlockingUrls.txt')
    ap.add_argument('--output', default='blocklist.txt')
    ap.add_argument('--report', default=None, help='write a Markdown run report here')
    args = ap.parse_args()

    with open(args.sources, encoding='utf-8') as fh:
        urls = [l.strip() for l in fh if l.strip() and not l.lstrip().startswith('#')]

    domains, rows, ok = set(), [], 0
    for url in urls:
        try:
            found = set(parse(fetch(url)))
            domains |= found
            ok += 1
            rows.append(f'| ✅ | {len(found):,} | {url} |')
        except (urllib.error.URLError, ValueError, OSError) as e:
            rows.append(f'| ❌ | {type(e).__name__}: {str(e)[:80]} | {url} |')
        print(rows[-1], flush=True)

    errors = []
    if not urls or ok / len(urls) < MIN_SOURCE_SUCCESS:
        errors.append(f'only {ok}/{len(urls)} sources downloaded (minimum {MIN_SOURCE_SUCCESS:.0%})')
    old = previous_domains(args.output)
    prev = len(old) if old else None
    if prev and abs(len(domains) - prev) / prev > MAX_CHANGE:
        errors.append(f'domain count {prev:,} -> {len(domains):,} changes more than ±{MAX_CHANGE:.0%}')

    summary = [f'Sources downloaded: **{ok}/{len(urls)}**',
               f'Domains: **{prev:,}** → **{len(domains):,}**' if prev else f'Domains: **{len(domains):,}**']
    report = '\n'.join(summary + ([''] + [f'**ABORTED:** {e}' for e in errors] if errors else []) +
                       ['', '| Status | Domains / error | Source |', '|---|---|---|'] + rows) + '\n'
    if args.report:
        with open(args.report, 'w', encoding='utf-8') as fh:
            fh.write(report)

    if errors:
        print('\n'.join(f'ERROR: {e}' for e in errors), file=sys.stderr)
        return 1

    if domains == old:                                         # no change: keep file (and its date header) as is
        print('No change in domains; output left untouched')
        return 0

    now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    with open(args.output, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(f'# Generated {now} from {ok}/{len(urls)} sources in {args.sources}\n')
        fh.write(f'# Domains: {len(domains)}\n')
        fh.write('\n'.join(sorted(domains)) + '\n')
    print(f'Wrote {len(domains):,} domains to {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
