#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Read-only coverage evidence: registry -> Storage bytes -> dated Geofabrik MD5."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

OFFICIAL_RPC = 'https://testnet.lez.logos.co'

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def canonical_snapshot(snapshot, catalog):
    region = catalog.get(snapshot['region'])
    if region is None:
        raise ValueError('Region outside canonical partition')
    for field in ('parent', 'level', 'source_url'):
        if snapshot[field] != region[field]:
            raise ValueError('Canonical hierarchy/source mismatch')
    version = snapshot['version']
    if type(version) is not int or not 20000101 <= version <= 20991231:
        raise ValueError('Invalid snapshot date')
    date = datetime.datetime.strptime(str(version), '%Y%m%d')
    if snapshot['hosted'] is not True or type(snapshot['bytes']) is not int or snapshot['bytes'] <= 0:
        raise ValueError('Incomplete hosting assertion')
    for key, size in [('checksum', 16), ('sha256', 32)]:
        digest = snapshot[key]
        if not isinstance(digest, list) or len(digest) != size or any(type(b) is not int or not 0 <= b <= 255 for b in digest):
            raise ValueError('Malformed snapshot digest')
    return region, region['source_url'].replace('-latest.osm.pbf', date.strftime('-%y%m%d.osm.pbf'))

def checksum(url):
    with urllib.request.build_opener(NoRedirect()).open(url+'.md5', timeout=30) as response:
        raw = response.read(4097)
    if len(raw) > 4096:
        raise ValueError('Oversized MD5 sidecar')
    text = raw.decode('ascii').strip()
    match = re.fullmatch(r'([a-fA-F0-9]{32})(?:\s+\*?([^\r\n]+))?', text)
    if not match or (match[2] and match[2] != url.rsplit('/', 1)[1]):
        raise ValueError('Malformed or mismatched MD5 sidecar')
    return match[1].lower()

def hash_file(path):
    md5, sha, size = hashlib.md5(), hashlib.sha256(), 0
    with path.open('rb') as stream:
        while block := stream.read(1024*1024):
            md5.update(block); sha.update(block); size += len(block)
    return dict(md5=md5.hexdigest(), sha256=sha.hexdigest(), bytes=size)

def coverage(verified, catalog):
    regions = sorted({row['region'] for row in verified})
    countries = sorted({catalog[region]['country'] for region in regions})
    return dict(regions=regions, countries=countries, region_count=len(regions), country_count=len(countries))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli', type=Path, required=True)
    p.add_argument('--rpc', default=OFFICIAL_RPC)
    p.add_argument('--program', required=True)
    p.add_argument('--storage', required=True)
    p.add_argument('--max-pages', type=int, default=64)
    p.add_argument('--max-file-bytes', type=int, default=2*1024**3)
    p.add_argument('--max-total-bytes', type=int, default=10*1024**3)
    p.add_argument('--scratch', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if min(a.max_pages, a.max_file_bytes, a.max_total_bytes) <= 0:
        p.error('Positive limits required')
    if a.output.exists():
        p.error('Output already exists; preserve previous evidence')
    a.cli = a.cli.resolve(strict=True)
    def call(*args):
        result = subprocess.run([str(a.cli), *map(str, args)], capture_output=True, text=True, timeout=900)
        if result.returncode:
            raise RuntimeError(result.stderr[-2000:])
        return json.loads(result.stdout)
    catalog = {r['path']:r for r in call('catalog')['canonical_regions']}
    report = dict(result='incomplete', scope='Observed registry and retrieved bytes at check time, not persistent availability, independent adoption or consensus finality.',
                  checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), rpc=a.rpc, program=a.program,
                  storage=a.storage, official_endpoint=a.rpc.rstrip('/')==OFFICIAL_RPC,
                  cli_sha256=hashlib.sha256(a.cli.read_bytes()).hexdigest(), verified=[], failed=[], complete_scan=False)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        report['coverage'] = coverage(report['verified'], catalog)
        report['coverage_threshold_met'] = (report['result']=='checked' and report['official_endpoint'] and report['complete_scan'] and
            report['coverage']['region_count'] >= 25 and report['coverage']['country_count'] >= 15)
        a.output.write_text(json.dumps(report, indent=2)+'\n')
    save()
    try:
        records, page, seen, count = [], 0, set(), None
        while page is not None:
            if type(page) is not int or page < 0 or page in seen or len(seen) >= a.max_pages:
                raise ValueError('Invalid pagination or scan budget exhausted')
            seen.add(page)
            response = call('registry-page', a.rpc, a.program, page, 'all', '')
            if count is None: count = response['catalog_count']
            if count != response['catalog_count']:
                raise ValueError('Registry changed during scan; retry with fresh evidence')
            records.extend(response['records']); page = response['next_page']
        if call('registry-page', a.rpc, a.program, 0, 'all', '')['catalog_count'] != count:
            raise ValueError('Registry changed at scan completion')
        if len(records) != count or {r['ordinal'] for r in records} != set(range(count)):
            raise ValueError('Incomplete or duplicate registry records')
        report['complete_scan'] = True
        report['catalog_count'] = count
        attempted_bytes, verified_regions = 0, set()
        a.scratch.mkdir(parents=True, exist_ok=True)
        for record in sorted(records, key=lambda r:(r['snapshot']['version'], r['timestamp']), reverse=True):
            snapshot = record['snapshot']
            if snapshot['region'] in verified_regions: continue
            try:
                region, source = canonical_snapshot(snapshot, catalog)
                size = snapshot['bytes']
                if size > a.max_file_bytes or attempted_bytes + size > a.max_total_bytes:
                    raise ValueError('Download byte budget exceeded')
                expected = checksum(source)
                if expected != bytes(snapshot['checksum']).hex():
                    raise ValueError('Registry checksum differs from canonical source')
                attempted_bytes += size
                with tempfile.TemporaryDirectory(prefix='map-coverage-', dir=a.scratch) as tmp:
                    dest = Path(tmp)/'snapshot.pbf'
                    call('download-snapshot', a.storage, json.dumps(snapshot), a.max_file_bytes, dest)
                    actual = hash_file(dest)
                if actual != dict(md5=expected, sha256=bytes(snapshot['sha256']).hex(), bytes=size):
                    raise ValueError('Downloaded bytes differ from source or registry')
                if checksum(source) != expected:
                    raise ValueError('Canonical checksum changed during download')
                report['verified'].append(dict(region=region['path'], country=region['country'], cid=snapshot['cid'],
                    version=snapshot['version'], source=source, registrant=record['registrant'], ordinal=record['ordinal'], **actual))
                verified_regions.add(region['path'])
            except Exception as error:
                report['failed'].append(dict(region=snapshot.get('region'), cid=snapshot.get('cid'), error=str(error)))
            save()
        report['result'] = 'checked'
    except Exception as error:
        report['error'] = str(error)
    finally: save()
    print(json.dumps({k:report[k] for k in ['result','coverage','coverage_threshold_met']}))
    return 0 if report['coverage_threshold_met'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
