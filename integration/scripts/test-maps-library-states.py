#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Render library states in actual packaged Basecamp using explicit UI fixture data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from fixture_process import stop_group

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--basecamp', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output = a.output.resolve()
a.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='maps-library-states-') as folder:
    profile = Path(folder).resolve()
    subprocess.run(['python3', str(ROOT/'scripts/install-maps-ui.py'), '--user-dir', str(profile)], check=True, stdout=subprocess.DEVNULL)
    receipt = json.loads((profile/'.maps-release-install.json').read_text())
    main = profile/'plugins/logos_maps/qml/Main.qml'
    original = main.read_text()
    # This is rendering evidence, deliberately not a live registry response.
    snapshot = dict(region='africa/ethiopia', parent=None, level='country',
                    cid='bafyRenderingFixtureOnly', source_url='https://download.geofabrik.de/africa/ethiopia-latest.osm.pbf',
                    checksum=[1]*16, sha256=[2]*32, bytes=3, version=20261009, hosted=True)
    injected = '''
    Timer {
        property int stage: 0
        property bool capturing: false
        property var captures: []
        interval: 350; repeat: true; running: true
        function labels(item, output) {
            if (!item.visible) return;
            if (typeof item.text === "string" && item.text.length) output.push(item.text);
            for (var i=0; i<item.children.length; ++i) labels(item.children[i], output);
        }
        onTriggered: {
            if (!control.ready || capturing) return;
            if (stage===0) {
                root.section=0; root.selected=control.regions.find(function(r){return r.path==="africa/ethiopia";});
                stage=1; return;
            }
            capturing=true;
            var texts=[];labels(root,texts);
            var label=["unknown","empty","announced"][stage-1];
            root.grabToImage(function(image){
                var path=__PREFIX__+"-"+label+".png";
                captures.push({state:label,texts:texts,image:path,saved:image.saveToFile(path)});
                if(stage===1) {
                    control.queryRegion="africa/ethiopia";
                    control.state=Object.assign({},control.state,{kind:"query",running:false,error:"",result:{records:[],next_page:null}});
                    stage=2;
                } else if(stage===2) {
                    control.state=Object.assign({},control.state,{result:{records:[{snapshot:__SNAPSHOT__,timestamp:1791611000000,ordinal:0,registrant:new Array(32).fill(1)}],next_page:null}});
                    stage=3;
                } else {stop();console.log("LIBRARY_STATES_DONE",JSON.stringify(captures));}
                capturing=false;
            });
        }
    }
'''.replace('__PREFIX__', json.dumps(str(a.output.with_suffix('')))).replace('__SNAPSHOT__', json.dumps(snapshot))
    assert original.count('    id: root') == 1
    main.write_text(original.replace('    id: root', '    id: root'+injected, 1))
    env = dict(os.environ, LOGOS_USER_DIR=str(profile), XDG_CONFIG_HOME=str(profile/'config'),
               XDG_CACHE_HOME=str(profile/'cache'), QT_QPA_PLATFORM='offscreen', QT_QUICK_BACKEND='software')
    with (profile/'runtime.log').open('w+') as log:
        child = subprocess.Popen([str(a.basecamp.resolve()), '--uri=basecamp://app/logos_maps'], env=env, stdout=log, stderr=log, start_new_session=True)
        try:
            deadline = time.monotonic()+60
            while time.monotonic()<deadline:
                time.sleep(.5); log.flush(); log.seek(0); output=log.read()
                match=re.search(r'LIBRARY_STATES_DONE ([^\n]+)',output)
                if match: break
                if child.poll() is not None: raise RuntimeError(output[-5000:])
            else: raise RuntimeError(output[-5000:])
            captures=json.loads(match[1])
        finally: stop_group(child)
    assert len(captures)==3 and all(c['saved'] for c in captures)
    assert 'Hosting availability has not been checked.' in captures[0]['texts']
    assert 'No announcements on this page.' in captures[1]['texts']
    assert 'Snapshot 20261009 · unverified claim' in captures[2]['texts']
    assert snapshot['cid'] in captures[2]['texts']
    for c in captures: c['image_sha256']=hashlib.sha256(Path(c['image']).read_bytes()).hexdigest()
    record=dict(result='passed', scope='Actual released QML rendering with synthetic UI state injection; no live query, hosting or adoption claim.',
                qml_sha256=hashlib.sha256(original.encode()).hexdigest(), runtime_packages=receipt['packages'], captures=captures)
    a.output.write_text(json.dumps(record,indent=2)+'\n')
    print('Unknown, empty-page and announced-snapshot UI states passed')
