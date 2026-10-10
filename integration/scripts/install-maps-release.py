#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Verify and install map LGX packages into previously unused module locations.

This is a local test/development installer, not catalog publication. Existing
module directories, application databases, and signing keys are never replaced.
"""
import argparse
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--profile', type=pathlib.Path, required=True)
p.add_argument('--lgx', type=pathlib.Path, required=True)
p.add_argument('--app-lgx', type=pathlib.Path)
p.add_argument('--publisher-lgx', type=pathlib.Path)
p.add_argument('--sdk-lgx', type=pathlib.Path)
p.add_argument('--distribution-lgx', type=pathlib.Path)
p.add_argument('--variant', choices=['linux-amd64','darwin-arm64'],
               help='Defaults to this host; explicit selection also permits offline extraction')
a = p.parse_args()
variant = a.variant
if variant is None:
    host = (platform.system(), platform.machine().lower())
    variant = {('Linux','x86_64'):'linux-amd64',
               ('Darwin','arm64'):'darwin-arm64',
               ('Darwin','aarch64'):'darwin-arm64'}.get(host)
    if variant is None:
        p.error('Unsupported host; select an explicit supported variant for offline extraction')
extension = '.dylib' if variant == 'darwin-arm64' else '.so'
if a.app_lgx and not a.publisher_lgx:
    p.error('The app requires its publisher package')
packages = [(a.sdk_lgx, 'prize_maps', 'core'),
            (a.publisher_lgx, 'maps_publisher', 'core'),
            (a.distribution_lgx, 'maps_distribution', 'core'),
            (a.app_lgx, 'logos_maps', 'ui_qml')]
packages = [row for row in packages if row[0]]
if not packages:
    p.error('Provide at least one package')
profile = a.profile.resolve()
for package, name, kind in packages:
    if not package.is_file():
        p.error(f'Package is missing: {package}')
    target = profile/('modules' if kind == 'core' else 'plugins')/name
    if target.exists() or target.is_symlink():
        p.error(f'Refusing to replace an existing module: {target}')
profile.mkdir(parents=True, exist_ok=True)
installed = []
receipts = []
with tempfile.TemporaryDirectory(prefix='.maps-release-', dir=profile) as temporary:
    staged = []
    for package, name, kind in packages:
        verification = subprocess.check_output([str(a.lgx), 'verify', str(package)], text=True)
        manifest = json.loads(subprocess.check_output(
            [str(a.lgx), 'manifest', str(package), '--json'], text=True))
        if manifest.get('name') != name or manifest.get('type') != kind:
            p.error(f'Package identity does not match {name}')
        main = manifest.get('main', {}).get(variant, '')
        if not main or pathlib.Path(main).name != main or not main.endswith(extension):
            p.error(f'Package has no supported {variant} plugin entry point')
        expected = ['maps_publisher'] if name == 'logos_maps' else []
        if name == 'logos_maps' and 'maps_distribution' in manifest.get('dependencies', []):
            expected.append('maps_distribution')
            if not a.distribution_lgx:
                p.error('This app package requires --distribution-lgx')
        if manifest.get('dependencies', []) != expected:
            p.error(f'Unexpected dependencies in {name}')
        output = pathlib.Path(temporary)/name
        subprocess.run([str(a.lgx), 'extract', str(package), '--variant',
                        variant, '--output', str(output)], check=True,
                       stdout=subprocess.DEVNULL)
        payload = output/variant
        if not (payload/main).is_file():
            p.error(f'Package entry point is missing: {name}')
        (payload/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        (payload/'metadata.json').write_text(json.dumps(
            dict(manifest, main=pathlib.Path(main).stem), indent=2)+'\n')
        (payload/'variant').write_text(variant+'\n')
        (payload/'.prize-suite-managed').write_text('Logos prize suite LGX installation\n')
        target = profile/('modules' if kind == 'core' else 'plugins')/name
        staged.append((payload, target))
        receipts.append({'name': name, 'variant': variant, 'package': str(package.resolve()),
                         'package_sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                         'unsigned': 'Package is unsigned' in verification,
                         'files_sha256': {str(f.relative_to(payload)): hashlib.sha256(f.read_bytes()).hexdigest()
                                          for f in payload.rglob('*') if f.is_file()}})
    try:
        for payload, target in staged:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise RuntimeError(f'Module appeared during installation: {target}')
            payload.rename(target)
            installed.append(target)
    except BaseException:
        for target in reversed(installed):
            shutil.rmtree(target)
        raise
receipt = {'profile': str(profile), 'packages': receipts,
           'scope': 'local verified LGX extraction and installation; no catalog publication'}
(profile/'.maps-release-install.json').write_text(json.dumps(receipt, indent=2)+'\n')
print(json.dumps(receipt, indent=2))
