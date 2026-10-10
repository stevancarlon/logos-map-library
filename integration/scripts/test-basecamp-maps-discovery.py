#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Live source discovery and network-independent cache in the actual Basecamp UI."""
import argparse,datetime,hashlib,json,os,pathlib,re,signal,subprocess,tempfile,time
root=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--basecamp',type=pathlib.Path,required=True)
a=parser.parse_args()
screenshot=root/'artifacts/maps-native-v03/live-catalog.png'
with tempfile.TemporaryDirectory(prefix='maps-catalog-ui-') as folder:
    profile=pathlib.Path(folder).resolve(strict=True)
    subprocess.run(['python3',root/'scripts/install-maps-ui.py','--user-dir',profile],check=True,stdout=subprocess.DEVNULL)
    receipt_path=profile/'.maps-release-install.json'
    release_receipt=json.loads(receipt_path.read_text()) if receipt_path.is_file() else None
    main=profile/'plugins/logos_maps/qml/Main.qml';original=main.read_text()
    def run(offline):
        injection='''
    Timer {
        property int phase:0
        interval:500;running:true;repeat:true
        onTriggered: {
            if(control.error || control.state.error) {console.log("CATALOG_UI_ERROR",control.error,control.state.error);stop();return;}
            if(phase===0 && control.ready) {
                root.section=0;
                if(__OFFLINE__) {
                    console.log("CATALOG_UI_DONE",JSON.stringify(control.sourceCatalog));stop();return;
                }
                control.refreshCatalog();phase=1;
            } else if(phase===1 && !control.state.running && control.state.kind==="discover") {
                if(!control.sourceCatalog.checked_at) {console.log("CATALOG_UI_ERROR","missing source cache");stop();return;}
                phase=2;
                Qt.callLater(function(){root.grabToImage(function(image){
                    image.saveToFile(__SCREENSHOT__);
                    console.log("CATALOG_UI_DONE",JSON.stringify(control.sourceCatalog));
                });});
                stop();
            }
        }
    }
'''
        injection=injection.replace('__OFFLINE__',json.dumps(offline)).replace('__SCREENSHOT__',json.dumps(str(screenshot)))
        main.write_text(original.replace('    id: root','    id: root'+injection,1))
        env=dict(os.environ,LOGOS_USER_DIR=str(profile),XDG_CONFIG_HOME=str(profile/'config'),
                 XDG_CACHE_HOME=str(profile/'cache'),QT_QPA_PLATFORM='offscreen',QT_QUICK_BACKEND='software')
        with (profile/('offline.log' if offline else 'online.log')).open('w+') as log:
            child=subprocess.Popen([str(a.basecamp.resolve()),'--uri=basecamp://app/logos_maps'],
                                   env=env,stdout=log,stderr=log,start_new_session=True)
            try:
                deadline=time.monotonic()+900
                while time.monotonic()<deadline:
                    time.sleep(.5);log.flush();log.seek(0);output=log.read()
                    if 'CATALOG_UI_DONE' in output:break
                    if 'CATALOG_UI_ERROR' in output or 'Failed to compile ui_qml view' in output or child.poll() is not None:
                        raise RuntimeError(output[-9000:])
                else:raise RuntimeError('Catalog UI timeout: '+output[-9000:])
                return json.loads(re.search(r'CATALOG_UI_DONE ([^\n]+)',output).group(1))
            finally:
                try:os.killpg(child.pid,signal.SIGTERM);child.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
                except ProcessLookupError:pass
    online=run(False)
    assert len(online['catalog']['index_sha256'])==64
    canonical=json.loads(subprocess.check_output([profile/'plugins/logos_maps/bin/maps-v03','catalog'],text=True))['canonical_regions']
    supported={r['path'] for r in canonical}
    available={r['path'] for r in online['catalog']['regions']}
    assert available <= supported and len(available)+len(online['catalog']['missing'])==72
    by_path={r['path']:r for r in canonical}
    for region in online['catalog']['regions']:
        expected=by_path[region['path']]
        assert all(region[field]==expected[field] for field in ['parent','level','source_url'])
    assert {r['region'] for r in online['versions']}==available
    for item in online['versions']:
        if item['source']:
            source=item['source']
            assert source['region']==item['region'] and isinstance(source['version'],int)
            assert source['dated_url'].startswith('https://download.geofabrik.de/'+item['region']+'-')
        else:assert item['error']
    # In this owned test profile, allow only the offline bundled catalog command.
    adapter=profile/'plugins/logos_maps/bin/maps-v03';real=adapter.with_name('maps-v03.real')
    adapter.rename(real)
    adapter.write_text("#!/usr/bin/env python3\nimport os,sys\nif sys.argv[1:]!=['catalog']:sys.exit('Network-capable command forbidden in offline cache check')\nos.execv("+repr(str(real))+",[str("+repr(str(real))+"),*sys.argv[1:]])\n")
    adapter.chmod(0o755)
    offline=run(True)
    assert offline==online and screenshot.is_file()
paths=['native/maps/qml/Main.qml','native/maps/qml/MapController.qml','native/backend/MapBackend.cpp',
       'lez-v03/maps-sdk/src/distribution.rs',
       'scripts/test-basecamp-maps-discovery.py',str(screenshot.relative_to(root))]
if not release_receipt:paths += ['native/maps/libmaps_backend.so','target/debug/maps-v03']
evidence={'result':'passed','scope':'actual Basecamp discovery handlers, live Geofabrik index and source-date reads; cached restart allows only the offline catalog command; no registry or public deployment',
          'runtime_packages':release_receipt['packages'] if release_receipt else None,
          'canonical_hierarchy_checked':True,
          'available_regions':len(available),'missing':online['catalog']['missing'],
          'available_versions':sum(bool(r['source']) for r in online['versions']),
          'source_catalog':online,'offline_restart_without_network_command':True,
          'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'sha256':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in paths}}
(root/'evidence/basecamp-maps-discovery.json').write_text(json.dumps(evidence,indent=2)+'\n')
print(json.dumps(evidence,indent=2))
