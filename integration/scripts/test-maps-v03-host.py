#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Canonical Ethiopia import/fetch + real isolated Storage + signed v0.3 SDK roundtrip."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
from fixture_process import install_termination_handler, run_monitored, stop_group

install_termination_handler()
root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--storage', type=Path, required=True)
parser.add_argument('--sequencer', type=Path, required=True)
parser.add_argument('--source', type=Path)
parser.add_argument('--version')
parser.add_argument('--mode', choices=['local', 'fetch'], default='local')
parser.add_argument('--basecamp', type=Path)
parser.add_argument('--bulk-fetch-ui', action='store_true')
parser.add_argument('--host-cli',type=Path)
args = parser.parse_args()
if args.host_cli and args.basecamp:parser.error('Choose terminal or Basecamp fixture')
if args.bulk_fetch_ui and not args.basecamp:parser.error('--bulk-fetch-ui requires Basecamp')
if not args.bulk_fetch_ui and not args.version:
    parser.error('A dated source version is required for the SDK fixture')
if not args.bulk_fetch_ui and args.mode == 'local' and not args.source:
    parser.error('Local import requires --source')
for path in [args.storage,args.sequencer]+([args.source] if args.source else []):
    if not path.is_file():
        parser.error(f'Missing input: {path}')
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
api = f'http://127.0.0.1:{port}/api/storage/v1'
log_path = root / f'artifacts/maps-v03-host-{args.mode}-storage.log'
with tempfile.TemporaryDirectory(prefix='logos-maps-v03-host-') as temporary:
    scratch = Path(temporary)
    with log_path.open('w') as log:
        process = subprocess.Popen([str(args.storage.resolve()), '--data-dir=' + str(scratch/'node'),
                                    '--api-bindaddr=127.0.0.1', '--api-port=' + str(port),
                                    '--listen-ip=127.0.0.1', '--nat=extip:127.0.0.1',
                                    '--no-bootstrap-node', '--num-threads=2', '--log-level=warn'],
                                   stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Storage exited before readiness')
                try:
                    with urllib.request.urlopen(api + '/debug/info', timeout=1) as response:
                        json.load(response)
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError('Storage not ready')
            env = dict(os.environ, MAPS_HOST_MODE=args.mode, MAPS_HOST_STORAGE_API=api,
                       MAPS_HOST_SOURCE=str(args.source.resolve()) if args.source else '', MAPS_HOST_VERSION=args.version or '')
            result = run_monitored(['python3', str(root/'scripts/test-v03-sequencer.py'),
                                    '--sequencer', str(args.sequencer.resolve()), '--suite', 'maps',
                                    '--scratch-dir', str(scratch)] + (['--maps-hosting-ui' if args.bulk_fetch_ui else '--maps-publishing-ui',str(args.basecamp.resolve())] if args.basecamp else ['--maps-host-cli',str(args.host_cli.resolve())] if args.host_cli else []), process,
                                   env=env, timeout=1800, capture_stdout=True)
            if result.returncode:
                raise RuntimeError(result.stdout or 'Host pipeline failed')
            record = json.loads(result.stdout)
            if record.get('result') != 'passed' or not (record.get('hosting') or record.get('combined_host_cli',{}).get('combined_host',{}).get('authentic_storage_roundtrip') or record.get('native_publishing_form',{}).get('authentic_storage_roundtrip') or record.get('native_hosting_form',{}).get('authentic_storage_roundtrip')):
                raise RuntimeError('Missing authentic hosting result')
            print(json.dumps(record, indent=2))
        finally:
            stop_group(process)
