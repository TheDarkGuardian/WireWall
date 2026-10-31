"""Record exact Go/npm versions and preserve installed license notices."""
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / 'docs' / 'third-party'

def notices(directory, target):
    copied = []
    if not directory.exists():
        return copied
    for path in directory.iterdir():
        if path.is_file() and re.match(r'^(licen[cs]e|copying|notice|copyright)(\.|$|-)', path.name, re.I):
            target.mkdir(parents=True, exist_ok=True)
            destination = target / (path.name + '.txt')
            destination.write_bytes(path.read_bytes())
            copied.append(destination.relative_to(ROOT / 'docs').as_posix())
    return copied

def main():
    raw = subprocess.check_output([str(ROOT/'.tools/go/bin/go.exe'), 'list', '-m', '-json', 'all'], cwd=ROOT, text=True)
    decoder = json.JSONDecoder()
    modules = []
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip()); raw = raw.lstrip()[end:]
        if not value.get('Main'):
            key = re.sub(r'[^\w.-]', '_', value['Path'])
            files = notices(Path(value.get('Dir', '/nonexistent')), DEST/'go'/key)
            modules.append({'name':value['Path'], 'version':value['Version'], 'notices':files})
    packages = []
    lock = json.loads((ROOT/'web/package-lock.json').read_text())
    for name, value in sorted(lock['packages'].items()):
        if not name:
            continue
        key = re.sub(r'[^\w.-]', '_', name)
        files = notices(ROOT/'web'/name, DEST/'npm'/key)
        packages.append({'name':name.removeprefix('node_modules/'), 'version':value.get('version'),
                         'license':value.get('license', 'package notice'), 'development':value.get('dev', False), 'notices':files})
    sdk_notices = notices(ROOT/'.tools/go', DEST/'go-sdk')
    result = {'go':modules, 'npm':packages, 'goSDKNotices':sdk_notices}
    DEST.mkdir(parents=True, exist_ok=True)
    (DEST/'inventory.json').write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = ['# Bağımlılık ve lisans envanteri', '',
             'Go sürümleri go.mod/go.sum; npm sürümleri package-lock.json üzerinden kaydedilir. Kurulu paketlerin üst dizin lisans/NOTICE dosyaları third-party altında aynen korunur. Bu liste hukuki uygunluk sertifikası değildir; yayımlamadan önce dağıtılan bileşenlerin bildirimleri incelenir.', '',
             'WireWall’ın özgün kaynak kodu [MIT lisansı](../LICENSE) ile yayımlanır. BPF kaynakları `GPL-2.0-only OR MIT` çift lisans bildirimini taşır. Üçüncü taraf bileşenler kendi lisanslarına tabidir. Grafana ve Prometheus kaynak pakete gömülmez, kendi paketleri/lisanslarıyla ayrıca kurulur.', '',
             '## Go', '', '| Modül | Sürüm | Bildirim |', '|---|---|---|']
    for value in modules:
        refs = ', '.join(f'[dosya]({path})' for path in value['notices']) or 'Kurulu modülde üst dizin bildirimi bulunamadı'
        lines.append(f"| {value['name']} | {value['version']} | {refs} |")
    lines += ['', '## npm (build/test bağımlılıkları dahil)', '', '| Paket | Sürüm | Paket lisans bilgisi | Kapsam |', '|---|---|---|---|']
    for value in packages:
        lines.append(f"| {value['name']} | {value['version']} | {value['license']} | {'geliştirme' if value['development'] else 'çalışma'} |")
    lines += ['', 'Makine tarafından okunabilir sürüm ve bildirim yolları: [inventory.json](third-party/inventory.json).', '',
              'Windows üzerinde farklı platformlara ait opsiyonel npm paketleri kurulu olmayabilir; bu girdiler sürüm/lisans metadatasıyla listelenir, olmayan dosya varmış gibi kopyalanmaz.', '',
              'Derleme araçları: resmi Go SDK (BSD bildirimi kopyalandı); Clang/LLVM, Linux UAPI ve libbpf başlıkları kendi lisanslarıyla ayrı sağlanır. Taşınabilir SDK/cache dosyaları kaynak arşivine alınmaz.']
    (ROOT/'docs/DEPENDENCIES.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps({'goModules':len(modules), 'npmPackages':len(packages), 'noticeFiles':sum(len(v['notices']) for v in modules+packages)+len(sdk_notices)}))

if __name__ == '__main__':
    main()
