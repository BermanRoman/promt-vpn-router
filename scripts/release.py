#!/usr/bin/env python3
"""Validate an explicit distribution file list; optionally build a text-only ZIP."""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import unicodedata
import zipfile


FILES = (
    '.gitignore', 'AGENTS.md', 'README.md', 'SKILL.md', 'START.md',
    'agents/openai.yaml', 'agents/infrastructure.md', 'agents/routing.md',
    'agents/router.md', 'agents/reviewer.md', 'assets/project.example.json',
    'references/intake.md', 'references/providers.md', 'references/routing.md',
    'references/servers.md', 'references/router.md', 'references/acceptance.md',
    'references/maintenance.md', 'references/state-format.md',
    'references/validation.md', 'scripts/case.py', 'scripts/test_case.py',
    'scripts/release.py',
)


def validate(root):
    errors, contents = [], {}
    for path in root.rglob('*'):
        relative = path.relative_to(root)
        if '.git' in relative.parts or '__pycache__' in relative.parts:
            continue
        if path.is_symlink():
            errors.append(str(relative) + ': symlink is not distributable')
        elif path.is_file() and relative.as_posix() not in FILES:
            errors.append(str(relative) + ': file absent from release allowlist')
    for name in FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            errors.append(name + ': missing file or symlink')
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            errors.append(name + ': not UTF-8 text')
            continue
        contents[name] = raw
        if any(unicodedata.category(c) == 'Cf' or (unicodedata.category(c) == 'Cc' and c not in '\n\r\t') for c in text):
            errors.append(name + ': invisible control character')
        # Heuristics complement the mandatory manual review; never print matches.
        if re.search(r'/(?:Users|home)/[A-Za-z0-9_.-]+/', text):
            errors.append(name + ': personal absolute path')
        if re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:vless|vmess|trojan)://|gh[pousr]_[A-Za-z0-9]{20,}', text):
            errors.append(name + ': possible credential')
        if path.suffix == '.md':
            for link in re.findall(r'\]\(([^\s)]+)\)', text):
                if '://' in link or link.startswith('#'):
                    continue
                target = (path.parent / link.split('#')[0]).resolve()
                try:
                    target_name = target.relative_to(root.resolve()).as_posix()
                except ValueError:
                    errors.append(name + ': link escapes distribution')
                    continue
                if target_name not in FILES:
                    errors.append(name + ': broken or non-distributed link')
    return errors, contents


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, help='Create a NEW ZIP outside this repository')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    errors, contents = validate(root)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        return 1
    print('Validated {} allowlisted UTF-8 files and local Markdown links.'.format(len(contents)))
    print('Secret heuristics passed; manual content review is still required.')
    if args.zip:
        output = args.zip.absolute()
        try:
            output.resolve().relative_to(root)
        except ValueError:
            pass
        else:
            print('ZIP must be outside the repository.', file=sys.stderr)
            return 1
        with zipfile.ZipFile(output, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in FILES:
                archive.writestr('home-vpn-agent/' + name, contents[name])
        print('ZIP SHA-256: ' + hashlib.sha256(output.read_bytes()).hexdigest())
    return 0


if __name__ == '__main__':
    sys.exit(main())
