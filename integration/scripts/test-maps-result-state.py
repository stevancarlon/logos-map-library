#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check the result panel after a rejected input using actual Basecamp and a disposable profile."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from fixture_process import install_termination_handler, stop_group
install_termination_handler()
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--basecamp',type=Path,required=True)
p.add_argument('--qml',type=Path,help='Explicit candidate Main.qml overlay; omitted tests released QML')
p.add_argument('--expect-visible',action='store_true',help='Reproduce the stale-panel baseline rather than require the fix')
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
screenshot=a.output.with_suffix('.png').resolve()
with tempfile.TemporaryDirectory(prefix='maps-result-state-') as folder:
    profile=Path(folder)
    subprocess.run(['python3',str(ROOT/'scripts/install-maps-ui.py'),'--user-dir',str(profile)],check=True,stdout=subprocess.DEVNULL)
    fixture=profile/'fixture.bin';fixture.write_bytes(b'abc')
    main=profile/'plugins/logos_maps/qml/Main.qml'
    qml=a.qml.read_text() if a.qml else main.read_text()
    original_hash=hashlib.sha256(qml.encode()).hexdigest()
    qml=qml.replace('            ScrollView {\n                contentWidth:', '            ScrollView {\n                id: testFileScroll\n                contentWidth:',1)
    assert 'id: testFileScroll' in qml
    injected='''
    Timer {
        property int phase:0
        interval:250;repeat:true;running:true
        onTriggered: {
            if(phase===0 && control.ready) {
                root.section=1;
                control.start({op:"verify",file:__FILE__,md5:"900150983cd24fb0d6963f7d28e17f72",limit:"3"});phase=1;
            } else if(phase===1 && !control.state.running && control.state.result.bytes===3) {
                if(control.error || control.state.error || !resultColumn.parent.visible) {
                    console.log("RESULT_STATE_ERROR","successful result not displayed");stop();return;
                }
                control.start({op:"verify",file:__FILE__,md5:"invalid",limit:"3"});phase=2;
            } else if(phase===2 && control.error) {
                phase=3;stop();
                Qt.callLater(function() {
                    testFileScroll.contentItem.contentY=Math.max(0,testFileScroll.contentItem.contentHeight-testFileScroll.availableHeight);
                    root.grabToImage(function(image) {
                    var saved=image.saveToFile(__IMAGE__);
                    console.log("RESULT_STATE_CAPTURE",JSON.stringify({error:control.error,visible:resultColumn.parent.visible,previous_bytes:control.state.result.bytes,image_saved:saved}));
                }); });
            }
        }
    }
'''.replace('__FILE__',json.dumps(str(fixture))).replace('__IMAGE__',json.dumps(str(screenshot)))
    assert qml.count('id: root')==1
    main.write_text(qml.replace('id: root','id: root'+injected,1))
    env=dict(os.environ,LOGOS_USER_DIR=str(profile),XDG_CONFIG_HOME=str(profile/'config'),XDG_CACHE_HOME=str(profile/'cache'),QT_QPA_PLATFORM='offscreen',QT_QUICK_BACKEND='software')
    with (profile/'runtime.log').open('w+') as log:
        child=subprocess.Popen([str(a.basecamp.resolve()),'--uri=basecamp://app/logos_maps'],env=env,stdout=log,stderr=log,start_new_session=True)
        try:
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                time.sleep(.25);log.flush();log.seek(0);output=log.read()
                match=re.search(r'RESULT_STATE_CAPTURE ([^\n]+)',output)
                if match:break
                if child.poll() is not None or 'RESULT_STATE_ERROR' in output or 'Failed to compile ui_qml view' in output:raise RuntimeError(output[-6000:])
            else:raise RuntimeError(output[-6000:])
            result=json.loads(match[1]);assert result['image_saved'] and screenshot.is_file()
            assert result['visible']==a.expect_visible,result
            result.update(result='passed',candidate_overlay=bool(a.qml),qml_sha256=original_hash,screenshot=str(screenshot),screenshot_sha256=hashlib.sha256(screenshot.read_bytes()).hexdigest(),scope='Synthetic three-byte file and invalid MD5 input in actual Basecamp; expect-visible mode reproduces the stale-success bug, not acceptance success.')
            a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
        finally:stop_group(child)
