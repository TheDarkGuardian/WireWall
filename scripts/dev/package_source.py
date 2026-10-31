"""Build a reviewable source archive without runtime state or credentials."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
import zipfile

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    skipped = {'.git', '.local', '.tools', 'node_modules', '__pycache__', 'data', 'bin', 'test-results', 'playwright-report'}
    manifest = []
    listed = subprocess.run(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=root, capture_output=True, check=True).stdout
    candidates = sorted({root/name.decode('utf-8') for name in listed.split(b'\0') if name})
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in candidates:
            relative = path.relative_to(root)
            if path.resolve() in {output, output.with_suffix('.manifest.json')}:
                continue
            if not path.is_file() or path.is_symlink() or any(part in skipped for part in relative.parts):
                continue
            if path.name.startswith('.env') or path.suffix in {'.token', '.password', '.secret', '.db', '.o', '.exe', '.zip', '.pyc', '.pem', '.key'}:
                continue
            raw = path.read_bytes()
            archive.writestr(relative.as_posix(), raw)
            manifest.append({'path': relative.as_posix(), 'sha256': hashlib.sha256(raw).hexdigest()})
    output.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print(json.dumps({'files':len(manifest), 'archive':str(output), 'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}))

if __name__ == '__main__':
    main()
