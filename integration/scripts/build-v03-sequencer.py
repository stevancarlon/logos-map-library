#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build the pinned official v0.3 standalone sequencer for local integration."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

REVISION = 'db66590ab821a4e142c211017a3866d007f6fa77'
ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--target-dir', type=Path, required=True)
args = parser.parse_args()
source = args.source.resolve()
if not args.target_dir.is_absolute():
    parser.error('--target-dir must be absolute')
head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
if head != REVISION:
    parser.error(f'Expected upstream revision {REVISION}, found {head}')
if subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=no'], text=True, env=dict(os.environ, GIT_OPTIONAL_LOCKS='0')).strip():
    parser.error('Upstream checkout has tracked modifications')
subprocess.run(['cargo', 'build', '--manifest-path', str(source / 'Cargo.toml'), '--locked',
                '-p', 'sequencer_service', '--features', 'standalone', '-j', '1'], check=True,
               env=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0',
                        CARGO_TARGET_DIR=str(args.target_dir)))
binary = args.target_dir / 'debug/sequencer_service'
destination = ROOT / 'artifacts/lez-v03-runtime/sequencer_service'
destination.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.sequencer-build-', delete=False) as tmp:
    staged = Path(tmp.name)
try:
    shutil.copy2(binary, staged)
    staged.replace(destination)
finally:
    staged.unlink(missing_ok=True)
with destination.open('rb') as stream:
    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
metadata = {'source_revision': head, 'features': ['standalone'], 'profile': 'dev, debug=0',
            'binary_sha256': digest, 'binary': str(destination),
            'scope': 'Locally built upstream fixture runtime; not a published release or validation result.'}
(destination.parent / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(json.dumps(metadata, indent=2))
