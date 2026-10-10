#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Patch pinned nixpkgs vendoring to isolate Git sources with duplicate crates.

Only source layout and Cargo replacement configuration change. Revision pins,
registry checksums, and canonical source downloads remain unchanged.
"""
import pathlib
import sys
p = pathlib.Path(sys.argv[1])
s = p.read_text()
changes = [
    ('\'directory = "@vendor@"\'', '\'directory = "@vendor@/registry"\''),
    ('    seen_source_keys = set()',
     '    (out_dir / "registry").mkdir()\n    seen_git_revisions = set()\n    seen_source_keys = set()'),
    ('        crate_out_dir = out_dir / dir_name',
     '        crate_out_dir = out_dir / "registry" / dir_name'),
    ('            git_tree = vendor_staging_dir / "git" / git_sha_rev',
     '            git_tree = vendor_staging_dir / "git" / git_sha_rev\n'
     '            git_vendor_dir = out_dir / "git" / git_sha_rev / "crates"\n'
     '            git_vendor_dir.mkdir(parents=True, exist_ok=True)\n'
     '            crate_out_dir = git_vendor_dir / dir_name\n'
     '            artifacts = git_tree / "artifacts"\n'
     '            artifact_target = git_vendor_dir.parent / "artifacts"\n'
     '            if artifacts.is_dir() and not artifact_target.exists():\n'
     '                shutil.copytree(artifacts, artifact_target)'),
    ('''            config_lines.append('replace-with = "vendored-sources"')''',
     '''            config_lines.append(f'replace-with = "vendored-git-{git_sha_rev}"')
            if git_sha_rev not in seen_git_revisions:
                config_lines.append(f'[source."vendored-git-{git_sha_rev}"]')
                config_lines.append(f'directory = "@vendor@/git/{git_sha_rev}/crates"')
                seen_git_revisions.add(git_sha_rev)'''),
]
for before, after in changes:
    if s.count(before) != 1:
        raise SystemExit('Pinned vendoring implementation changed: patch refused')
    s = s.replace(before, after)
p.write_text(s)
