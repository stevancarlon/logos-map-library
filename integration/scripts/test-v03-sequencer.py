#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Run native approval/outbox/fee checks on a disposable v0.3 standalone sequencer."""
import argparse
import datetime
import hashlib
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

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--sequencer', type=Path, required=True)
parser.add_argument('--suite', choices=['native', 'token', 'cli', 'basecamp', 'basecamp-ui', 'owner-native', 'owner-tokens', 'sdk-tokens', 'private', 'maps'], default='native')
parser.add_argument('--client', type=Path)
parser.add_argument('--basecamp', type=Path)
parser.add_argument('--maps-sdk-lgx', type=Path)
parser.add_argument('--lgx', type=Path)
parser.add_argument('--maps-publisher', type=Path)
parser.add_argument('--maps-bulk', type=Path)
parser.add_argument('--maps-cli', type=Path)
parser.add_argument('--maps-publishing-ui', type=Path)
parser.add_argument('--maps-cross-page', action='store_true')
parser.add_argument('--maps-hosting-ui', type=Path)
parser.add_argument('--maps-host-cli', type=Path)
parser.add_argument('--scratch-dir', type=Path, default=ROOT / '.tmp')
args = parser.parse_args()
evidence_name = args.suite
if args.maps_sdk_lgx or args.lgx:
    if not (args.maps_sdk_lgx and args.lgx and args.suite == 'maps' and args.basecamp):
        parser.error('--maps-sdk-lgx and --lgx require maps suite and --basecamp')
    if not args.maps_sdk_lgx.is_file() or not args.lgx.is_file():
        parser.error('SDK package or official lgx executable not found')
    evidence_name = 'maps-release-query'
if args.maps_publisher:
    if args.suite != 'maps' or not args.maps_publisher.is_file():
        parser.error('--maps-publisher requires the maps suite and a built fixture executable')
    evidence_name = 'maps-publisher'
if args.maps_bulk:
    if args.suite != 'maps' or not args.maps_bulk.is_file():
        parser.error('--maps-bulk requires maps suite and built fixture')
    evidence_name = 'maps-bulk'
if args.maps_cli:
    if args.suite != 'maps' or not args.maps_cli.is_file():
        parser.error('--maps-cli requires the maps suite and built terminal client')
    evidence_name = 'maps-cli'
if args.maps_publishing_ui:
    if args.suite != 'maps' or not args.maps_publishing_ui.is_file():
        parser.error('--maps-publishing-ui requires maps suite and Basecamp executable')
    evidence_name = 'maps-publishing-ui'
if args.maps_cross_page:
    if not args.maps_publishing_ui or os.environ.get('MAPS_HOST_MODE'):
        parser.error('--maps-cross-page requires a standalone publishing UI fixture')
    evidence_name = 'maps-cross-page-ui'
if args.suite == 'maps' and os.environ.get('MAPS_HOST_MODE'):
    if os.environ['MAPS_HOST_MODE'] not in ('local', 'fetch'):
        parser.error('MAPS_HOST_MODE must be local or fetch')
    evidence_name = 'maps-host-' + os.environ['MAPS_HOST_MODE'] + ('-basecamp' if args.maps_publishing_ui else '')
if args.maps_hosting_ui:
    if args.suite != 'maps' or not args.maps_hosting_ui.is_file() or not os.environ.get('MAPS_HOST_STORAGE_API'):
        parser.error('--maps-hosting-ui requires maps suite, Basecamp and isolated Storage environment')
    evidence_name = 'maps-authentic-bulk-ui'
if args.maps_host_cli:
    if args.suite != 'maps' or not args.maps_host_cli.is_file() or not os.environ.get('MAPS_HOST_SOURCE'):
        parser.error('--maps-host-cli needs maps suite, binary and authentic hosting environment')
    evidence_name = 'maps-combined-host-cli'
if args.basecamp and not args.basecamp.is_file():
    parser.error('Basecamp executable not found')
if args.suite in ('basecamp', 'basecamp-ui', 'owner-native', 'owner-tokens', 'sdk-tokens') and (not args.basecamp or not args.basecamp.is_file()):
    parser.error('The Basecamp suite requires --basecamp APPIMAGE')
clients={'native':'native-chain','token':'token-chain','cli':'token-chain','basecamp':'basecamp-chain','basecamp-ui':'basecamp-chain','owner-native':'basecamp-chain','owner-tokens':'token-chain','sdk-tokens':'token-chain','private':'private-chain','maps':'maps-chain'}
args.client = args.client or ROOT / 'target/debug/examples' / clients[args.suite]
extra=[]
if args.suite=='cli': extra=['--cli']
elif args.suite=='sdk-tokens': extra=['--sdk-ui',str(args.basecamp.resolve())]
elif args.suite=='owner-tokens': extra=['--owner-ui',str(args.basecamp.resolve())]
elif args.suite in ('basecamp','basecamp-ui','owner-native'):
    extra=[str(args.basecamp.resolve())]
    if args.suite=='basecamp-ui':extra.append('--production-ui')
    if args.suite=='owner-native':extra.append('--owner-ui')
executor = os.environ.get('RISC0_SERVER_PATH', '')
if not executor or not Path(executor).is_file() or not os.access(executor, os.X_OK):
    parser.error('Set RISC0_SERVER_PATH to the official executable r0vm 3.0.5')
for binary in (args.sequencer, args.client):
    if not binary.is_file():
        parser.error(f'Missing binary: {binary}')
if args.suite in ('cli', 'private') and not (ROOT / 'target/debug/lez-v03-wallet').is_file():
    parser.error('Build the lez-v03-wallet binary first')
if not args.scratch_dir.is_dir():
    parser.error('Scratch directory must exist')
with args.client.open('rb') as binary:
    client_hash = hashlib.file_digest(binary, 'sha256').hexdigest()
account = subprocess.check_output([str(args.client.resolve()), 'fixture-account'], text=True, timeout=10).strip()
with socket.socket() as listener:
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
endpoint = f'http://127.0.0.1:{port}'
with tempfile.TemporaryDirectory(prefix='logos-v03-sequencer-', dir=args.scratch_dir) as scratch:
    scratch = Path(scratch)
    config = {
        'home': str(scratch / 'state'), 'metrics_address': None, 'gossip': None,
        'max_num_tx_in_block': 20, 'max_block_size': '1 MiB', 'mempool_max_size': 1000,
        'block_create_timeout': {'native': '500ms', 'token': '2s', 'cli': '5s', 'basecamp': '5s', 'basecamp-ui': '5s', 'owner-native': '5s', 'owner-tokens': '5s', 'sdk-tokens': '5s', 'private': '5s', 'maps': '1s'}[args.suite], 'retry_pending_blocks_timeout': '500ms',
        'bedrock_config': {
            'backoff': {'start_delay': '100ms', 'max_retries': 2},
            'channel_id': '01' * 32, 'node_url': 'http://127.0.0.1:1', 'funding_key': '01' * 32,
            'channel_params': {'minimum_sequencer_stake': 149, 'posting_timeframe': 300,
                               'posting_timeout': 25, 'exit_delay': 100},
        },
        'genesis': [{'supply_account': {'account_id': account, 'balance': 10000000000}}],
        'signing_key': [37] * 32,
    }
    config_path = scratch / 'config.json'
    config_path.write_text(json.dumps(config))
    log_path = ROOT / f'artifacts/lez-v03-{evidence_name}-sequencer.log'
    with log_path.open('w') as log:
        process = subprocess.Popen([str(args.sequencer.resolve()), str(config_path), '--listen-address',
                                    '127.0.0.1', '--port', str(port)], stdout=log, stderr=log,
                                   env=dict(os.environ, RUST_LOG='warn', RISC0_DEV_MODE='0',
                                            RISC0_EXECUTOR='ipc', RISC0_PROVER='ipc'), start_new_session=True)
        try:
            for _ in range(120):
                if process.poll() is not None:
                    raise RuntimeError(f'Sequencer exited during startup: {process.returncode}')
                try:
                    request = urllib.request.Request(endpoint, data=json.dumps({
                        'jsonrpc': '2.0', 'id': 1, 'method': 'getFeeState', 'params': []
                    }).encode(), headers={'Content-Type': 'application/json'})
                    with urllib.request.urlopen(request, timeout=1) as response:
                        value = json.load(response)
                    if isinstance(value.get('result'), dict) and 'height' in value['result']:
                        break
                except (OSError, ValueError):
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError('v0.3 sequencer did not become ready')
            if args.suite == 'private':
                preflight = run_monitored(['python3', str(ROOT / 'scripts/test-v03-private-cli.py'),
                                           '--rpc', endpoint], process, capture_stdout=True, timeout=600)
                if preflight.returncode:
                    raise RuntimeError((preflight.stdout or '') + ' Private CLI preflight failed')
            client_env = dict(os.environ)
            # The UI must create the authentic hosting assertion itself; the
            # SDK-only scenario tests that same assertion in a separate run.
            if args.maps_publishing_ui or args.maps_hosting_ui or args.maps_host_cli:
                client_env.pop('MAPS_HOST_MODE', None)
            result = run_monitored([str(args.client.resolve()), endpoint, str(scratch / 'outbox.sqlite')] + extra,
                                   process, env=client_env, capture_stdout=True, timeout={'native': 240, 'token': 900, 'cli': 1800, 'basecamp': 1800, 'basecamp-ui': 1800, 'owner-native': 1800, 'owner-tokens': 1800, 'sdk-tokens': 2400, 'private': 21600, 'maps': 1800}[args.suite])
            if result.returncode:
                raise RuntimeError((result.stdout or '') + f' Client exited {result.returncode}')
            if args.suite == 'private' and args.basecamp:
                recovery = run_monitored(['python3', str(ROOT / 'scripts/test-basecamp-v03-private-recovery.py'),
                                          '--basecamp', str(args.basecamp.resolve()), '--wallet', str(scratch / 'outbox.sqlite'),
                                          '--rpc', endpoint, '--rotated-fixture'], process, capture_stdout=True, timeout=600)
                if recovery.returncode:
                    raise RuntimeError((recovery.stdout or '') + ' Private Basecamp recovery failed')
            evidence = json.loads(result.stdout)
            if evidence.get('result') != 'passed':
                raise RuntimeError('Client did not report success')
            if args.suite == 'maps' and os.environ.get('MAPS_COVERAGE_CLI'):
                if not evidence.get('hosting'):
                    raise RuntimeError('Coverage verifier fixture requires authentic hosting')
                report_path = scratch / 'coverage-check.json'
                checked = run_monitored(['python3', str(ROOT/'scripts/verify-maps-coverage.py'),
                    '--cli', os.environ['MAPS_COVERAGE_CLI'], '--rpc', endpoint,
                    '--program', evidence['program_account'], '--storage', os.environ['MAPS_HOST_STORAGE_API'],
                    '--scratch', str(scratch/'coverage'), '--output', str(report_path)],
                    process, capture_stdout=True, timeout=900)
                report = json.loads(report_path.read_text())
                if checked.returncode != 1 or report['result'] != 'checked' or report['coverage_threshold_met'] or report['official_endpoint']:
                    raise RuntimeError('Isolated coverage fixture must remain nonqualifying')
                if report['coverage']['regions'] != ['africa/ethiopia']:
                    raise RuntimeError('Only the authentic Ethiopia fixture may verify')
                evidence['coverage_verifier'] = report
            if args.suite == 'maps' and os.environ.get('MAPS_HOSTED_OFFLINE_CLI'):
                if not evidence.get('hosting'):
                    raise RuntimeError('Offline-hosted regression requires an authentic hosting record')
                offline = run_monitored(['python3',str(ROOT/'scripts/test-maps-hosted-offline.py'),
                    '--cli',os.environ['MAPS_HOSTED_OFFLINE_CLI'],'--rpc',endpoint,
                    '--program',evidence['program_account'],'--storage',os.environ['MAPS_HOST_STORAGE_API'],
                    '--snapshot',json.dumps(evidence['hosting']['snapshot'])],process,capture_stdout=True,timeout=600)
                if offline.returncode:raise RuntimeError((offline.stdout or '')+' Offline hosted regression failed')
                evidence['hosted_without_source']=json.loads(offline.stdout)
            if args.maps_bulk:
                bulk_result = run_monitored([str(args.maps_bulk.resolve()), endpoint,
                    evidence['program_account'], str(scratch / 'maps-bulk.sqlite')],
                    process, capture_stdout=True, timeout=900)
                if bulk_result.returncode:
                    raise RuntimeError((bulk_result.stdout or '') + ' Maps bulk planner failed')
                evidence['bulk_registration'] = json.loads(bulk_result.stdout)
                if evidence['bulk_registration'].get('result') != 'passed':
                    raise RuntimeError('Bulk planner did not report success')
                evidence['bulk_binary_sha256'] = hashlib.sha256(args.maps_bulk.read_bytes()).hexdigest()
            if args.maps_publisher:
                publisher_result = run_monitored([str(args.maps_publisher.resolve()), endpoint,
                    evidence['program_account'], str(scratch / 'maps-publisher.sqlite')],
                    process, capture_stdout=True, timeout=300)
                if publisher_result.returncode:
                    raise RuntimeError((publisher_result.stdout or '') + ' Maps publisher failed')
                evidence['publisher'] = json.loads(publisher_result.stdout)
                if evidence['publisher'].get('result') != 'passed':
                    raise RuntimeError('Maps publisher did not report success')
                evidence['publisher_binary_sha256'] = hashlib.sha256(args.maps_publisher.read_bytes()).hexdigest()
            if args.maps_cli:
                cli_result = run_monitored(['python3', str(ROOT / 'scripts/test-maps-publish-cli.py'),
                    '--rpc', endpoint, '--program', evidence['program_account'],
                    '--binary', str(args.maps_cli.resolve())], process, capture_stdout=True, timeout=600)
                if cli_result.returncode:
                    raise RuntimeError((cli_result.stdout or '') + ' Maps terminal publisher failed')
                evidence['terminal_publisher'] = json.loads(cli_result.stdout)
                if evidence['terminal_publisher'].get('result') != 'passed':
                    raise RuntimeError('Maps terminal publisher did not report success')
            if args.maps_host_cli:
                hosted_cli = run_monitored(['python3',str(ROOT/'scripts/test-maps-publish-cli.py'),
                    '--rpc',endpoint,'--program',evidence['program_account'],'--binary',str(args.maps_host_cli.resolve()),
                    '--storage',os.environ['MAPS_HOST_STORAGE_API'],'--source',os.environ['MAPS_HOST_SOURCE'],
                    '--version',os.environ['MAPS_HOST_VERSION']],process,capture_stdout=True,timeout=1200)
                if hosted_cli.returncode:raise RuntimeError((hosted_cli.stdout or '')+' Combined host CLI failed')
                evidence['combined_host_cli']=json.loads(hosted_cli.stdout)
            if args.maps_hosting_ui:
                hosted = run_monitored(['python3',str(ROOT/'scripts/test-basecamp-maps-hosting.py'),
                    '--basecamp',str(args.maps_hosting_ui.resolve()),'--rpc',endpoint,
                    '--program',evidence['program_account'],'--storage',os.environ['MAPS_HOST_STORAGE_API']],
                    process,capture_stdout=True,timeout=1500)
                if hosted.returncode:raise RuntimeError((hosted.stdout or '')+' Authentic bulk form failed')
                evidence['native_hosting_form']=json.loads(hosted.stdout)
            if args.maps_publishing_ui:
                form_result=run_monitored(['python3',str(ROOT/'scripts/test-basecamp-maps-publishing.py'),
                    '--basecamp',str(args.maps_publishing_ui.resolve()),'--rpc',endpoint,
                    '--program',evidence['program_account']] + (['--cross-page'] if args.maps_cross_page else []) + ([
                        '--bulk','--storage',os.environ['MAPS_HOST_STORAGE_API'],
                        '--source',os.environ['MAPS_HOST_SOURCE'],'--version',os.environ['MAPS_HOST_VERSION']
                    ] if os.environ.get('MAPS_HOST_MODE') else []),process,capture_stdout=True,timeout=1200)
                if form_result.returncode:raise RuntimeError((form_result.stdout or '')+' Map publishing form failed')
                evidence['native_publishing_form']=json.loads(form_result.stdout)
            if args.suite == 'maps' and args.basecamp:
                ui_result = run_monitored(['python3', str(ROOT / 'scripts/test-basecamp-map-sdk.py'),
                                          '--basecamp', str(args.basecamp.resolve()), '--protocol', 'v03',
                                          '--rpc', endpoint, '--program', evidence['program_account'],
                                          '--region', 'south-america/argentina',
                                          *(['--sdk-lgx', str(args.maps_sdk_lgx.resolve()), '--lgx', str(args.lgx.resolve())] if args.maps_sdk_lgx else [])], process,
                                         capture_stdout=True, timeout=600)
                if ui_result.returncode:
                    raise RuntimeError((ui_result.stdout or '') + ' Basecamp maps v0.3 query failed')
                evidence['basecamp_sdk_query'] = json.loads(ui_result.stdout)
                distribution_result = run_monitored(['python3', str(ROOT / 'scripts/test-basecamp-maps.py'),
                                          '--basecamp', str(args.basecamp.resolve()), '--rpc', endpoint,
                                          '--program', evidence['program_account']], process,
                                         capture_stdout=True, timeout=600)
                if distribution_result.returncode:
                    raise RuntimeError((distribution_result.stdout or '') + ' Basecamp distribution v0.3 query failed')
                evidence['basecamp_distribution_query']=json.loads(distribution_result.stdout)
                if os.environ.get('MAPS_RELEASE_DISTRIBUTION_LGX'):
                    consumer_result = run_monitored([
                        'python3', str(ROOT/'scripts/test-basecamp-map-distribution-consumer.py'),
                        '--basecamp',str(args.basecamp.resolve()),'--rpc',endpoint,
                        '--program',evidence['program_account'],
                        '--lgx',os.environ['MAPS_RELEASE_LGX'],
                        '--app-lgx',os.environ['MAPS_RELEASE_APP_LGX'],
                        '--publisher-lgx',os.environ['MAPS_RELEASE_PUBLISHER_LGX'],
                        '--distribution-lgx',os.environ['MAPS_RELEASE_DISTRIBUTION_LGX']],
                        process,capture_stdout=True,timeout=600)
                    if consumer_result.returncode:
                        raise RuntimeError((consumer_result.stdout or '')+' Distribution core query failed')
                    evidence['distribution_core_consumer']=json.loads(
                        (ROOT/'evidence/basecamp-maps-distribution-consumer.json').read_text())
            evidence['checked_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            evidence['client_binary_sha256'] = client_hash
            if args.suite == 'maps':
                paths = [ROOT / 'artifacts/maps-v03/program.elf',
                         ROOT / 'lez-v03/Cargo.lock',
                         ROOT / 'scripts/test-v03-sequencer.py', ROOT / 'scripts/test-maps-publish-cli.py']
                for folder in ('maps-core', 'maps-sdk', 'maps-guest', 'maps-publisher'):
                    paths.extend((ROOT / 'lez-v03' / folder).rglob('*.rs'))
                    paths.append(ROOT / 'lez-v03' / folder / 'Cargo.toml')
                paths.extend((ROOT / 'maps/src').rglob('*.rs'))
                paths.extend([ROOT / 'maps/Cargo.toml', ROOT / 'maps/data/catalog.json'])
                evidence['sha256'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in paths}
            evidence['sequencer_log'] = str(log_path.relative_to(ROOT))
            evidence['fixture_block_interval'] = config['block_create_timeout']
            with args.sequencer.open('rb') as binary:
                evidence['sequencer_binary_sha256'] = hashlib.file_digest(binary, 'sha256').hexdigest()
            (ROOT / f'evidence/lez-v03-{evidence_name}-chain.json').write_text(json.dumps(evidence, indent=2) + '\n')
            print(json.dumps(evidence, indent=2))
        except Exception:
            log.flush()
            print(log_path.read_text()[-12000:])
            raise
        finally:
            stop_group(process)
