#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Offline rejection and counting tests; never evidence of public coverage."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('coverage_verifier', Path(__file__).with_name('verify-maps-coverage.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
ROOT = Path(__file__).resolve().parents[1]
CATALOG = {r['path']:r for r in json.loads((ROOT/'maps/data/catalog.json').read_text())['canonical_regions']}

class CoverageTests(unittest.TestCase):
    def snapshot(self):
        row = CATALOG['africa/ethiopia']
        return dict(region=row['path'], parent=row['parent'], level=row['level'], source_url=row['source_url'],
                    version=20261009, bytes=3, hosted=True, checksum=[1]*16, sha256=[2]*32)

    def test_canonical_date_and_hierarchy(self):
        snapshot = self.snapshot()
        _, url = v.canonical_snapshot(snapshot, CATALOG)
        self.assertEqual(url, 'https://download.geofabrik.de/africa/ethiopia-261009.osm.pbf')
        for field, bad in [('version',20260230), ('parent','china'), ('region','not/canonical'),
                           ('source_url','https://example.com/file'), ('checksum',[True]*16), ('bytes',True)]:
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                v.canonical_snapshot(dict(snapshot, **{field:bad}), CATALOG)

    def test_mirrors_and_versions_do_not_inflate_coverage(self):
        rows=[dict(region='asia/china/guangdong')]*30+[dict(region='asia/china/henan')]*20
        result=v.coverage(rows,CATALOG)
        self.assertEqual((result['region_count'],result['country_count']),(2,1))

    def test_download_hashes_are_computed_from_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'file';p.write_bytes(b'abc')
            self.assertEqual(v.hash_file(p),dict(bytes=3,md5='900150983cd24fb0d6963f7d28e17f72',
                sha256='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'))

    def test_checksum_filename_and_length_are_checked(self):
        url='https://download.geofabrik.de/africa/ethiopia-261009.osm.pbf'
        for body, valid in [(b'1'*32+b'  ethiopia-261009.osm.pbf\n',True),
                            (b'1'*32+b'  kenya-261009.osm.pbf\n',False), (b'x'*4097,False)]:
            opener=types.SimpleNamespace(open=lambda *args,**kwargs:io.BytesIO(body))
            with patch.object(v.urllib.request,'build_opener',return_value=opener):
                if valid:self.assertEqual(v.checksum(url),'1'*32)
                else:
                    with self.assertRaises(ValueError):v.checksum(url)

    def run_scan(self, page):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cli=root/'fake-cli';cli.write_text('offline fixture')
            argv=['verify','--cli',str(cli),'--program','fixture','--storage','http://127.0.0.1:1',
                  '--scratch',str(root/'scratch'),'--output',str(root/'report.json')]
            def invoke(args,**kwargs):
                payload={'canonical_regions':list(CATALOG.values())} if args[1]=='catalog' else page
                return types.SimpleNamespace(returncode=0,stdout=json.dumps(payload),stderr='')
            with patch.object(sys,'argv',argv),patch.object(v.subprocess,'run',side_effect=invoke),contextlib.redirect_stdout(io.StringIO()):
                code=v.main()
            return code,json.loads((root/'report.json').read_text())

    def test_empty_registry_does_not_qualify(self):
        code,report=self.run_scan(dict(records=[],catalog_count=0,next_page=None))
        self.assertEqual(code,1);self.assertFalse(report['coverage_threshold_met'])
        self.assertTrue(report['complete_scan']);self.assertEqual(report['coverage']['region_count'],0)

    def test_incomplete_or_cyclic_scan_cannot_qualify(self):
        for page in [dict(records=[],catalog_count=1,next_page=None),dict(records=[],catalog_count=0,next_page=0)]:
            code,report=self.run_scan(page)
            self.assertEqual(code,1);self.assertFalse(report['complete_scan'])
            self.assertFalse(report['coverage_threshold_met']);self.assertIn('error',report)

if __name__=='__main__':unittest.main()
