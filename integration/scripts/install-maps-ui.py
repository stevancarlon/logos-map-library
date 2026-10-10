#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Install Map Library and its owner-only publisher module. Never modifies the separate Forum plugin."""
import argparse,json,os,pathlib,shutil,tempfile,subprocess
root=pathlib.Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser()
p.add_argument('--user-dir',type=pathlib.Path,default=root/'.local/basecamp')
a=p.parse_args()
release_args=[os.environ.get(name) for name in ['MAPS_RELEASE_APP_LGX','MAPS_RELEASE_PUBLISHER_LGX','MAPS_RELEASE_LGX']]
if any(release_args):
    if not all(release_args):p.error('Set all three MAPS_RELEASE_* package/tool variables')
    subprocess.run(['python3',str(root/'scripts/install-maps-release.py'),'--profile',str(a.user_dir),
                    '--app-lgx',release_args[0],'--publisher-lgx',release_args[1],'--lgx',release_args[2],
                    *(['--distribution-lgx',os.environ['MAPS_RELEASE_DISTRIBUTION_LGX']] if os.environ.get('MAPS_RELEASE_DISTRIBUTION_LGX') else [])],check=True)
    raise SystemExit(0)
dest=a.user_dir/'plugins/logos_maps'
marker=dest/'.prize-suite-managed'
if dest.exists() and not marker.exists(): raise SystemExit('Refusing to replace an existing plugin not managed by this suite')
core=a.user_dir/'modules/maps_publisher'
core_marker=core/'.prize-suite-managed'
if core.exists() and not core_marker.exists(): raise SystemExit('Refusing to replace unmanaged publisher module')
build=root/'artifacts/maps-publisher/build'
for name in ['maps_publisher.so','liblogos_maps_v03_publisher.so']:
    if not (build/name).is_file(): raise SystemExit('Build the native publisher first: build-maps-sdk-native.py --protocol publisher')
distribution_build=root/'artifacts/maps-distribution/build'
for name in ['maps_distribution.so','liblogos_maps_v03_sdk.so']:
    if not (distribution_build/name).is_file():raise SystemExit('Build distribution core first: build-maps-sdk-native.py --protocol distribution')
distribution_core=a.user_dir/'modules/maps_distribution'
if distribution_core.exists() and not (distribution_core/'.prize-suite-managed').exists():
    raise SystemExit('Refusing to replace unmanaged distribution core')
source=root/'native/maps' 
for needed in [source/'libmaps_backend.so',root/'target/debug/maps-v03']:
    if not needed.is_file(): raise SystemExit(f'Build first; missing {needed}')
dest.mkdir(parents=True,exist_ok=True)
def copy_atomic(src,target):
    target.parent.mkdir(parents=True,exist_ok=True)
    fd,path=tempfile.mkstemp(prefix='.install-',dir=target.parent);os.close(fd)
    try: shutil.copy2(src,path);os.replace(path,target)
    finally:
        if os.path.exists(path): os.unlink(path)
core.mkdir(parents=True,exist_ok=True)
meta=json.loads((root/'native/maps-publisher/metadata.json').read_text())
# Native module code only; key vaults and SQLite outboxes remain outside installation paths.
for name in ['maps_publisher.so','liblogos_maps_v03_publisher.so']: copy_atomic(build/name,core/name)
(core/'metadata.json').write_text(json.dumps(dict(meta,main='maps_publisher')))
(core/'manifest.json').write_text(json.dumps(dict(meta,manifestVersion='0.6.0',main={'linux-amd64':'maps_publisher.so'})))
(core/'variant').write_text('linux-amd64\n')
core_marker.write_text('Logos prize suite managed publisher module\n')
distribution_core.mkdir(parents=True,exist_ok=True)
for name in ['maps_distribution.so','liblogos_maps_v03_sdk.so']:
    copy_atomic(distribution_build/name,distribution_core/name)
meta=json.loads((root/'native/maps-distribution/metadata.json').read_text())
(distribution_core/'metadata.json').write_text(json.dumps(dict(meta,main='maps_distribution')))
(distribution_core/'manifest.json').write_text(json.dumps(dict(meta,manifestVersion='0.6.0',main={'linux-amd64':'maps_distribution.so'})))
(distribution_core/'variant').write_text('linux-amd64\n')
(distribution_core/'.prize-suite-managed').write_text('Logos prize suite managed distribution core\n')

for folder in ['qml','assets']:
    for file in (source/folder).rglob('*'):
        if file.is_file(): copy_atomic(file,dest/file.relative_to(source))
for name in ['metadata.json','manifest.json','variant']:
    copy_atomic(source/name,dest/name)
copy_atomic(source/'libmaps_backend.so',dest/'maps_backend.so')
copy_atomic(root/'target/debug/maps-v03',dest/'bin/maps-v03')
for license in ['LICENSE-MIT','LICENSE-APACHE']:copy_atomic(root/license,dest/license)
marker.write_text('Logos prize suite managed development plugin\n')
print(f'Installed Map Library at {dest}')
