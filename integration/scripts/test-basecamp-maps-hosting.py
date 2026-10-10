#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Authentic two-region Basecamp fetch/store/register/query/download handlers."""
import argparse, datetime, hashlib, json, os, pathlib, platform, re, signal, subprocess, tempfile, time
from urllib.parse import urlsplit
root=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
for name in ('basecamp','rpc','program','storage'):p.add_argument('--'+name,required=True)
a=p.parse_args()
for endpoint in (a.rpc,a.storage):
    u=urlsplit(endpoint)
    if u.scheme!='http' or u.hostname!='127.0.0.1' or not u.port:p.error('Disposable loopback nodes only')
def digest(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
with tempfile.TemporaryDirectory(prefix='maps-hosting-form-') as folder:
    # Resolve macOS /var -> /private/var before SQLite's NOFOLLOW check.
    profile=pathlib.Path(folder).resolve(strict=True);downloads=profile/'downloads';downloads.mkdir()
    keys=profile/'keys'
    subprocess.run([root/'target/debug/examples/native-publisher-fixture',keys],check=True)
    subprocess.run(['python3',root/'scripts/install-maps-ui.py','--user-dir',profile],check=True,stdout=subprocess.DEVNULL)
    receipt_path=profile/'.maps-release-install.json'
    release_receipt=json.loads(receipt_path.read_text()) if receipt_path.is_file() else None
    main=profile/'plugins/logos_maps/qml/Main.qml';original=main.read_text()
    def run(recovery):
        injected='''
    Timer {
        property int phase:0
        property int index:0
        property var reviewed:null
        interval:500;running:true;repeat:true
        onTriggered: {
            var c=publishing.controller;
            if(c.error || control.error || control.state.error) {console.log("HOST_FORM_ERROR",c.error,control.error,control.state.error);stop();return;}
            if(phase===0 && control.ready) {
                control.settings(__RPC__,__PROGRAM__,__STORAGE__);phase=1;
            } else if(phase===1 && control.state.program===__PROGRAM__) {
                publishing.keyPath=__KEY__;publishing.outboxPath=__OUTBOX__;
                publishing.keyPassword="maps-native-fixture";publishing.outboxPassword="maps-native-fixture";
                publishing.unlock();phase=2;
            } else if(phase===2 && c.unlocked && !c.busy) {
                if(publishing.keyPassword.length || publishing.outboxPassword.length) {console.log("HOST_FORM_ERROR","password retained");stop();return;}
                if(__RECOVERY__) {
                    if(publishing.snapshots.length!==2) {console.log("HOST_FORM_ERROR","queue lost");stop();return;}
                    publishing.chooseAll();publishing.prepare();phase=12;return;
                }
                root.section=4;root.checkedRegions=["africa/ethiopia","africa/kenya","africa/egypt"];
                bulk.excluded=["africa/egypt"];bulk.downloadDirectory=__DIRECTORY__;bulk.maximumBytes="500000000";
                control.checkUpdates(root.checkedRegions);phase=3;
            } else if(phase===3 && !control.state.running && control.updates.length===3) {
                if(bulk.selected.length!==2) {console.log("HOST_FORM_ERROR","opt-out failed");stop();return;}
                console.log("HOST_FORM_SOURCE_DATES",JSON.stringify(control.updates));
                bulk.begin();phase=4;
            } else if(phase===4 && !control.state.running && control.state.kind==="store_bulk") {
                var rows=control.state.bulk_outcomes;
                if(rows.length!==2 || rows.some(function(r){return r.state!=="stored";}) || publishing.snapshots.length!==2) {
                    console.log("HOST_FORM_ERROR","bulk storage failed",JSON.stringify(rows));stop();return;
                }
                console.log("HOST_FORM_STORED",JSON.stringify(publishing.snapshots));
                root.section=3;publishing.chooseAll();publishing.prepare();phase=5;
            } else if(phase===5 && !c.busy && c.review) {
                reviewed=c.review;console.log("HOST_FORM_REVIEW",JSON.stringify(reviewed));c.approve();phase=6;
            } else if(phase===6 && !c.busy && c.lastSubmission) {
                c.reconcile(c.lastSubmission.hash);phase=7;
            } else if(phase===7 && !c.busy) {
                if(c.history.length===1 && c.history[0].status==="observed") {
                    control.query(publishing.snapshots[index].region,0);phase=8;
                } else c.reconcile(c.lastSubmission.hash);
            } else if(phase===8 && !control.state.running && control.state.kind==="query") {
                var expected=publishing.snapshots[index];
                var record=control.state.result.records.find(function(r){return JSON.stringify(r.snapshot)===JSON.stringify(expected);});
                if(!record) {console.log("HOST_FORM_ERROR","registered snapshot absent");stop();return;}
                console.log("HOST_FORM_RECORD",JSON.stringify(record));
                root.chooseRecord(record);
                control.start({op:"download_snapshot",snapshot:record.snapshot,file:__DIRECTORY__+"/retrieved-"+index+".pbf",limit:"500000000"});phase=9;
            } else if(phase===9 && !control.state.running && control.state.kind==="download_snapshot") {
                index++;
                if(index<2) {control.query(publishing.snapshots[index].region,0);phase=8;}
                else {console.log("HOST_FORM_DONE",JSON.stringify({snapshots:publishing.snapshots,history:c.history,review:reviewed}));stop();}
            } else if(phase===12 && !c.busy && c.completion && !c.review) {
                console.log("HOST_FORM_RECOVERED",JSON.stringify(c.history));stop();
            }
        }
    }
'''
        replacements={'__RPC__':a.rpc,'__PROGRAM__':a.program,'__STORAGE__':a.storage,
            '__KEY__':str(keys/'key.vault'),'__OUTBOX__':str(keys/'outbox.sqlite'),
            '__RECOVERY__':recovery,'__DIRECTORY__':str(downloads)}
        for k,v in replacements.items():injected=injected.replace(k,json.dumps(v))
        main.write_text(original.replace('    id: root','    id: root'+injected,1))
        env=dict(os.environ,LOGOS_USER_DIR=str(profile),XDG_CONFIG_HOME=str(profile/'config'),
            XDG_CACHE_HOME=str(profile/'cache'),QT_QPA_PLATFORM='offscreen',QT_QUICK_BACKEND='software')
        marker='HOST_FORM_RECOVERED' if recovery else 'HOST_FORM_DONE'
        with (profile/('recovery.log' if recovery else 'hosting.log')).open('w+') as log:
            child=subprocess.Popen([a.basecamp,'--uri=basecamp://app/logos_maps'],env=env,
                stdout=log,stderr=log,start_new_session=True)
            try:
                deadline=time.monotonic()+1200
                while time.monotonic()<deadline:
                    time.sleep(.5);log.flush();log.seek(0);output=log.read()
                    if marker in output:break
                    if 'HOST_FORM_ERROR' in output or 'Failed to compile ui_qml view' in output or child.poll() is not None:
                        raise RuntimeError(output[-12000:])
                else:raise RuntimeError('Hosting form timeout: '+output[-12000:])
                assert 'maps-native-fixture' not in output
                value=json.loads(re.search(marker+r' ([^\n]+)',output).group(1))
                if not recovery:
                    records=[json.loads(raw) for raw in re.findall(r'HOST_FORM_RECORD ([^\n]+)',output)]
                    assert len(records)==2
                    batch=value['review']['instruction']['RegisterBatch']
                    for i,record in enumerate(records):
                        assert record['timestamp']==batch['timestamp'] and record['ordinal']==batch['expected_count']+i
                return value
            finally:
                try:os.killpg(child.pid,signal.SIGTERM);child.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                except ProcessLookupError:pass
    result=run(False);recovered=run(True)
    assert len(recovered)==1 and recovered[0]['hash']==result['history'][0]['hash']
    assert {s['region'] for s in result['snapshots']}=={'africa/ethiopia','africa/kenya'}
    for i,snapshot in enumerate(result['snapshots']):
        source=downloads/(snapshot['region'].replace('/','-')+'-'+str(snapshot['version'])+'.osm.pbf')
        assert source.stat().st_size==snapshot['bytes'] and digest(source)==bytes(snapshot['sha256']).hex()
        assert digest(downloads/f'retrieved-{i}.pbf')==digest(source)
paths=['native/maps/qml/Main.qml','native/maps/qml/BulkPanel.qml','native/maps/qml/PublisherPanel.qml',
       'native/maps/qml/PublisherController.qml','native/backend/MapBackend.cpp','native/maps/libmaps_backend.so',
       'artifacts/maps-publisher/build/liblogos_maps_v03_publisher.so','scripts/test-basecamp-maps-hosting.py']
if release_receipt:
    paths=[path for path in paths if not path.endswith('.so')]
evidence=dict(result='passed',platform=platform.system()+'-'+platform.machine(),scope='actual Basecamp form handlers; authentic live Ethiopia and Kenya extracts, isolated Storage and disposable v0.3 sequencer; no public hosting or coverage',
    authentic_storage_roundtrip=True,source_date_refresh=True,per_region_opt_out=True,registered_snapshot_downloads=True,
    basecamp_restart_completion=True,snapshots=result['snapshots'],hash=result['history'][0]['hash'],
    checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    sha256={f:digest(root/f) for f in paths})
if release_receipt:
    evidence['runtime_packages']=release_receipt['packages']
(root/'evidence/basecamp-maps-authentic-bulk.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps(evidence,indent=2))
