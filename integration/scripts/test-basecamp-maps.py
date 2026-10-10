#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Load the actual map plugin in a disposable Basecamp profile and verify CLI IPC."""
import sys
import argparse
import json
import http.server
import threading
import os
import pathlib
import signal
import subprocess
import tempfile
import platform
import time

root = pathlib.Path(__file__).resolve().parent.parent
out=root/'artifacts/maps-native-v03';out.mkdir(exist_ok=True)
parser = argparse.ArgumentParser()
parser.add_argument('--basecamp', type=pathlib.Path, required=True)
parser.add_argument('--rpc')
parser.add_argument('--program')
args = parser.parse_args()
if bool(args.rpc) != bool(args.program): parser.error('Supply both --rpc and --program')
if args.rpc:
    import re
    if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]+',args.rpc): parser.error('Loopback fixture RPC required')
if not args.basecamp.is_file():
    parser.error('Basecamp executable is missing')

with tempfile.TemporaryDirectory(prefix='logos-maps-basecamp-') as directory:
    profile = pathlib.Path(directory)
    subprocess.run(['python3', str(root / 'scripts/install-maps-ui.py'),
                    '--user-dir', str(profile)], check=True, stdout=sys.stderr)
    receipt_path=profile/'.maps-release-install.json'
    release_receipt=json.loads(receipt_path.read_text()) if receipt_path.exists() else None
    fixture = profile / 'checksum-fixture.bin'
    fixture.write_bytes(b'abc')
    controller = profile / 'plugins/logos_maps/qml/MapController.qml'
    class FixtureStorage(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/api/storage/v1/data/bafyFixture/network/stream':
                self.send_error(404); return
            self.send_response(200); self.send_header('Content-Length','3'); self.end_headers(); self.wfile.write(b'abc')
        def log_message(self,*args): pass
    storage=http.server.ThreadingHTTPServer(('127.0.0.1',0),FixtureStorage)
    threading.Thread(target=storage.serve_forever,daemon=True).start()
    snapshot={'region':'africa/ethiopia','parent':None,'level':'country','cid':'bafyFixture','source_url':'https://download.geofabrik.de/africa/ethiopia-latest.osm.pbf','checksum':list(bytes.fromhex('900150983cd24fb0d6963f7d28e17f72')),'sha256':list(bytes.fromhex('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')),'bytes':3,'version':20261008,'hosted':True}
    download=profile/'verified-download.bin'
    rejected=profile/'rejected-download.bin'
    qml = controller.read_text().replace('id: ctl','id: ctl\n    property int testStage: 0',1)
    marker = 'console.log("MAP_LIBRARY_READY", regions.length);'
    assert qml.count(marker) == 1
    qml = qml.replace(marker, marker + '\nctl.start(' + json.dumps({
        'op': 'verify', 'file': str(fixture),
        'md5': '900150983cd24fb0d6963f7d28e17f72', 'limit': '3'
    }) + ');')
    poll_marker = 'state = r;\n            polling = false;'
    assert qml.count(poll_marker) == 1
    settings={'op':'settings','rpc':'http://127.0.0.1:1','program':'','storage':f'http://127.0.0.1:{storage.server_port}/api/storage/v1'}
    command={'op':'download_snapshot','file':str(download),'limit':'3','snapshot':snapshot}
    bad_command={'op':'download_snapshot','file':str(rejected),'limit':'3','snapshot':dict(snapshot,sha256=[1]*32)}
    check = """
            if (testStage === 0 && !r.running && r.kind === "verify" && !r.error && r.result.bytes === 3) {
                testStage = 1;
                console.log("MAP_CLI_VERIFIED_IN_BASECAMP");
                ctl.call(SETTINGS, function () { ctl.start(DOWNLOAD); });
            } else if (testStage === 1 && !r.running && r.kind === "download_snapshot" && !r.error && r.result.bytes === 3) {
                testStage = 2;
                console.log("MAP_SNAPSHOT_VERIFIED_IN_BASECAMP");
                ctl.start(BAD_DOWNLOAD);
            } else if (testStage === 2 && !r.running && r.kind === "download_snapshot" && r.error) {
                testStage = 3;
                console.log("MAP_SNAPSHOT_CORRUPTION_REJECTED_IN_BASECAMP");
            }
    """.replace('SETTINGS',json.dumps(settings)).replace('BAD_DOWNLOAD',json.dumps(bad_command)).replace('DOWNLOAD',json.dumps(command))
    qml = qml.replace(poll_marker, poll_marker+check)
    if args.rpc:
        query_settings=dict(settings,rpc=args.rpc,program=args.program)
        qml=qml.replace('console.log("MAP_SNAPSHOT_CORRUPTION_REJECTED_IN_BASECAMP");',
            'console.log("MAP_SNAPSHOT_CORRUPTION_REJECTED_IN_BASECAMP");\nctl.call('+json.dumps(query_settings)+', function () { ctl.query("south-america/argentina",0); });')
        qml=qml.replace(poll_marker,poll_marker+'''
            if(testStage===3 && !r.running && r.kind==="query" && !r.error && r.result.records && r.result.records.length===1) {
                testStage=4; console.log("MAP_V03_QUERY_IN_BASECAMP",JSON.stringify(r.result));
            }
        ''')
    controller.write_text(qml)
    screenshot=out/'registry-query.png'
    update_screenshot=out/'update-check.png'
    if args.rpc:
        main=profile/'plugins/logos_maps/qml/Main.qml'
        text=main.read_text()
        capture='''
    Timer {
        property int captureStage: 0
        interval:500; running:true; repeat:true
        onTriggered: {
            if(captureStage===0 && control.ready && !control.state.running && control.state.kind==="query" && !control.state.error && control.state.result.records) {
                root.selected=control.regions.find(function(r) { return r.path==="south-america/argentina"; });
                root.showDetail=true; captureStage=1;
                Qt.callLater(function() { root.grabToImage(function(image) {
                    image.saveToFile(__OUTPUT_IMAGE__); console.log("MAP_V03_SCREENSHOT_DONE");
                    root.checkedRegions=["south-america/argentina", "africa/ethiopia"];
                    control.checkUpdates(root.checkedRegions);
                }); });
            } else if(captureStage===1 && !control.state.running && control.state.kind==="updates" && !control.state.error && control.updates.length===2) {
                captureStage=2; stop();
                console.log("MAP_V03_UPDATES_IN_BASECAMP", JSON.stringify(control.updates));
                Qt.callLater(function() { root.grabToImage(function(image) { image.saveToFile(__UPDATE_IMAGE__); console.log("MAP_V03_UPDATES_SCREENSHOT_DONE"); }); });
            }
        }
    }
'''.replace('__OUTPUT_IMAGE__',json.dumps(str(screenshot))).replace('__UPDATE_IMAGE__',json.dumps(str(update_screenshot)))
        main.write_text(text.replace('id: root','id: root'+capture,1))
    env = dict(os.environ, LOGOS_USER_DIR=str(profile),
               XDG_CONFIG_HOME=str(profile/'config'),
               QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software')
    with (profile / 'basecamp.log').open('w+') as log:
        process = subprocess.Popen([str(args.basecamp.resolve()),
                                    '--uri=basecamp://app/logos_maps'],
                                   env=env, stdout=log, stderr=log,
                                   start_new_session=True)
        try:
            output = ''
            for _ in range(240):
                time.sleep(0.5)
                log.flush()
                log.seek(0)
                output = log.read()
                if ('MAP_V03_UPDATES_SCREENSHOT_DONE' if args.rpc else 'MAP_SNAPSHOT_CORRUPTION_REJECTED_IN_BASECAMP') in output:
                    break
                if 'Failed to compile ui_qml view' in output:
                    raise RuntimeError('Test view did not compile: '+output[-5000:])
                if process.poll() is not None:
                    raise RuntimeError('Basecamp exited before bridge verification\n' + output[-5000:])
            else:
                raise RuntimeError('Basecamp bridge did not verify the fixture\n' + output[-5000:])
            assert 'MAP_LIBRARY_READY 72' in output
            assert 'MAP_SNAPSHOT_VERIFIED_IN_BASECAMP' in output
            assert download.read_bytes()==b'abc' and not rejected.exists()
            evidence = {
                'protocol':'lez-v0.3',
                'basecamp': '0.3.2', 'qt': '6.9.2', 'platform': platform.system().lower()+'-'+platform.machine().lower(),
                'ui_loaded': True, 'catalog_count': 72,
                'native_bridge_cli_checksum_test': True,
                'registered_snapshot_sha256_and_size_checked':True,
                'wrong_registered_sha256_rejected_before_publication':True,
                'scope': 'disposable local profile, synthetic three-byte file and loopback Storage HTTP fixture; no real Storage node, map hosting or chain action from UI',
                'host_storage_initialization_error': 'Should create metadata store!' in output,
                'real_v03_registry_query':bool(args.rpc),
            }
            if args.rpc:
                import re
                query=json.loads(re.search(r'MAP_V03_QUERY_IN_BASECAMP ([^\n]+)',output).group(1))
                assert query['records'][0]['snapshot']['region']=='south-america/argentina'
                evidence['registry_query']=query
                updates=json.loads(re.search(r'MAP_V03_UPDATES_IN_BASECAMP ([^\n]+)',output).group(1))
                assert [u['source']['region'] for u in updates]==['south-america/argentina','africa/ethiopia']
                assert updates[0]['registry_version']==query['records'][0]['snapshot']['version']
                assert updates[1]['registry_version'] is None
                for u in updates:
                    assert u['update_available']==(u['registry_version'] is not None and u['registry_version']<u['source']['version'])
                    assert u['verification']=='unverified_hosting_assertions'
                evidence['live_canonical_update_check']=updates
                assert update_screenshot.is_file()
                evidence['update_screenshot']=str(update_screenshot.relative_to(root))
                assert screenshot.is_file()
                evidence['screenshot']=str(screenshot.relative_to(root))
            import hashlib
            paths=[root/'native/maps/libmaps_backend.so',root/'target/debug/maps-v03',
                   root/'native/backend/MapBackend.cpp',root/'native/maps/qml/Main.qml',
                   root/'native/maps/qml/MapController.qml',root/'scripts/test-basecamp-maps.py']
            if release_receipt:
                paths=paths[2:]
                evidence['runtime_packages']=release_receipt['packages']
                evidence['scope']+='; runtime installed from verified portable LGX packages'
            if args.rpc: paths.extend([screenshot,update_screenshot])
            evidence['sha256']={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
            (root / ('evidence/basecamp-maps-v03-lgx.json' if release_receipt else 'evidence/basecamp-maps-v03.json')).write_text(json.dumps(evidence, indent=2) + '\n')
            print(json.dumps(evidence, indent=2))
        finally:
            storage.shutdown(); storage.server_close()
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            except ProcessLookupError:
                pass
