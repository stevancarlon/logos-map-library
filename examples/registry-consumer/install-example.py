#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Install the standalone SDK and first-party explorer into a new profile."""
import argparse,json,pathlib,shutil,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--profile',type=pathlib.Path,required=True)
p.add_argument('--sdk-lgx',type=pathlib.Path,required=True)
p.add_argument('--lgpm',type=pathlib.Path,required=True)
a=p.parse_args()
profile=a.profile.resolve()
if profile.exists() or profile.is_symlink():p.error('Choose a fresh profile directory')
if not a.sdk_lgx.is_file() or not a.lgpm.is_file():p.error('SDK package and package-manager executable are required')
profile.mkdir(parents=True)
subprocess.run([str(a.lgpm.resolve()),'--modules-dir',str(profile/'modules'),
               '--ui-plugins-dir',str(profile/'plugins'),'--allow-unsigned',
               'install','--file',str(a.sdk_lgx.resolve())],check=True)
core=profile/'modules/prize_maps'
if not core.is_dir() or sorted(p.name for p in (profile/'modules').iterdir())!=['prize_maps']:
    raise RuntimeError('Expected only the standalone SDK')
manifest=json.loads((core/'manifest.json').read_text())
if manifest['name']!='prize_maps' or manifest.get('dependencies'):
    raise RuntimeError('Expected standalone SDK metadata without dependencies')
source=pathlib.Path(__file__).resolve().parent
consumer=profile/'plugins/prize_maps_consumer'
consumer.mkdir(parents=True)
shutil.copytree(source/'qml',consumer/'qml')
meta=json.loads((source/'metadata.json').read_text())
(consumer/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
(consumer/'manifest.json').write_text(json.dumps(dict(meta,manifestVersion='0.6.0'),indent=2)+'\n')
(consumer/'variant').write_bytes((core/'variant').read_bytes())
print('Installed first-party SDK explorer; distribution app absent:',profile)
