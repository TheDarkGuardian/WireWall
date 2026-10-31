"""Install a checksum-verified portable Go SDK inside this workspace only."""
from pathlib import Path
import hashlib
import json
import platform
import urllib.request
import zipfile

root = Path(__file__).resolve().parents[2]
if platform.system() != "Windows" or platform.machine().lower() not in ("amd64", "x86_64"):
    raise SystemExit("This helper targets Windows x64. Install Go from https://go.dev/dl/ on other platforms.")
tools = root / ".tools"
tools.mkdir(exist_ok=True)
with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=30) as response:
    releases = json.load(response)
artifact = next(f for release in releases if release["stable"] for f in release["files"]
                if f["os"] == "windows" and f["arch"] == "amd64" and f["kind"] == "archive")
archive = tools / artifact["filename"]
if not archive.exists():
    urllib.request.urlretrieve("https://go.dev/dl/" + artifact["filename"], archive)
actual = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
if actual != artifact["sha256"]:
    raise SystemExit("SDK checksum mismatch; refusing to extract")
with zipfile.ZipFile(archive) as package:
    for member in package.infolist():
        target = (tools / member.filename).resolve()
        if not target.is_relative_to(tools.resolve()):
            raise SystemExit("Unsafe archive member")
    package.extractall(tools)
(tools / "go-sdk.json").write_text(json.dumps(artifact, indent=2), encoding="utf-8")
print(f"Verified {artifact['version']}: {tools / 'go' / 'bin' / 'go.exe'}")
