# Gerçek Grafana/Prometheus kurulumu ve işletimi

Mevcut VDS'de kuruldu ve doğrulandı. Buradaki adımlar temiz Ubuntu için tekrar kurulum tarifidir; çalışan VDS'de körlemesine yeniden uygulanmaz. Çekirdek kurulum ve kernel/namespace kapıları önce [INSTALL-REMOVE.md](INSTALL-REMOVE.md) üzerinden tamamlanır. İzleme kural/politika değiştirmez.

## Bileşenler ve erişim

Agent Unix socket → düşük yetkili `wirewall metrics` exporter127.0.0.1:9878 → Prometheus127.0.0.1:9090 → Grafana127.0.0.1:3000. Grafana kullanıcı girişi ister. Panel127.0.0.1:9876 kalır. Yeni public port açılmaz. KaynakIP/ruleID gibi etiketler metrik serilerine taşınmaz. Exporter eski gözlem>10s içinup0 döndürür ve stale sayaçları çıkarmaz. Dashboard ayrıca Prometheus scrapeup kontrol eder.

SSH tüneli: yerel9880→9876 ve9881→3000. WireWall için `http://127.0.0.1:9880/`, Grafana için **`http://localhost:9881/d/wirewall-l4/wirewall`** kullanın. Cookie'ler portla ayrılmadığından farklı hostname bilerek seçildi. Kalıcı root_url farklı tünel adı/portuyla kullanılacaksa `grafana.ini` güncellenir.

## Temiz kurulum

Root shell içinde, kaynak `/opt/wirewall` ve `wirewall` kullanıcısı hazır olmalıdır. Grafana'nın [resmi Debian signedAPT kurulumunu](https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/) kullanın. Mevcut kurulum ayrı `/etc/apt/sources.list.d/wirewall-grafana.list`, anahtar `/etc/apt/keyrings/wirewall-grafana.asc` kullanır. Kurulumda ölçülen anahtarSHA256 `d8f5f6f4c174c3b9184cb6ebbf691a2ee69831a109425de4e821f5b43c53a2f8`; anahtar rotasyonu olursa kaynağı yeniden doğrulayın.

Grafana başlamadan önce güvenli loopback config hazırlanır. Yeni kurulumda paket kullanıcısı henüz yoksa önce grup/kullanıcıyı resmi paketin beklediği biçimde oluşturun veya geçici systemd startup engeliyle paketi kurup config'i hazırlayın. Bu proje mevcut VDS'de config'i paket başlamadan hazırladı. Uygulanan sürüm13.3.0, tam sistem upgrade yapılmadı.

```bash
install -d -o root -g grafana -m 0750 /etc/wirewall-monitoring
python3 - <<'PY'
from pathlib import Path
import secrets, os, grp
for name in ['grafana-admin.secret','grafana-signing.secret']:
    p=Path('/etc/wirewall-monitoring')/name
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    with os.fdopen(fd,'w') as f: f.write(secrets.token_urlsafe(48)+'\n')
    os.chown(p,0,grp.getgrnam('grafana').gr_gid)
PY
install -o root -g grafana -m 0640 /opt/wirewall/deploy/monitoring/grafana.ini /etc/grafana/grafana.ini
install -d -o root -g grafana -m 0750 /var/lib/grafana/dashboards/wirewall
install -m 0644 /opt/wirewall/deploy/monitoring/wirewall-dashboard.json /var/lib/grafana/dashboards/wirewall/wirewall-dashboard.json
install -m 0644 /opt/wirewall/deploy/monitoring/grafana-datasource.yml /etc/grafana/provisioning/datasources/wirewall.yml
install -m 0644 /opt/wirewall/deploy/monitoring/grafana-dashboards.yml /etc/grafana/provisioning/dashboards/wirewall.yml
```

Secret üretimi mevcut dosyanın üzerine yazmaz. Admin parolası ilk veritabanı kurulumunda kullanılır; sonradan dosyayı değiştirmek Grafana DB parolasını otomatik döndürmez. Resmi Grafana parola yönetimi/CLI ile kontrollü değiştirilir. Secrets raporlara/argv'ye girmez. [File provider](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/) `$__file{...}` config içinde kullanılır.

Prometheus: [resmi release](https://github.com/prometheus/prometheus/releases/tag/v3.15.1), linux-amd64v3.15.1 arşiviSHA256 **6a726885328ad9efebbf36e876ce2fb6225468a71fd1e7ce3ba666d5f4d97a84**. Resmi sha256sums.txt ile doğruladıktan sonra link/path escape içermediği kontrol edilen arşivi `/opt/wirewall-monitoring/prometheus-3.15.1` altına açın; root sahipli, executable0755. `/opt/wirewall-monitoring/prometheus` buna symlink'tir. Farklı sürüm/mimari için bu hash kullanılmaz.

```bash
useradd --system --home-dir /var/lib/wirewall-prometheus --shell /usr/sbin/nologin wirewall-prometheus
install -d -o root -g wirewall-prometheus -m 0750 /etc/wirewall-prometheus
install -o root -g wirewall-prometheus -m 0640 /opt/wirewall/deploy/monitoring/prometheus.yml /etc/wirewall-prometheus/prometheus.yml
install -m 0644 /opt/wirewall/deploy/wirewall-metrics.service /etc/systemd/system/wirewall-metrics.service
install -m 0644 /opt/wirewall/deploy/wirewall-prometheus.service /etc/systemd/system/wirewall-prometheus.service
/opt/wirewall-monitoring/prometheus/promtool check config /etc/wirewall-prometheus/prometheus.yml
systemctl daemon-reload
systemctl enable --now wirewall-metrics wirewall-prometheus grafana-server
```

Kullanıcı zaten varsa useradd tekrarlanmaz. StateDirectory servis tarafından0700 oluşturulur. Prometheus ayrı kullanıcı ve sıfır capability ile30gün/2GB saklar. Nft/BPF sayaçları yeniden yüklemede sıfırlanabilir; PromQLrate reset'i ele alır. Grafana JSON üretimi `python scripts/dev/build_dashboard.py`; provision dosyası değişirse UI'dan kaydedilmiş düzenin üzerine gelebilir. Kalıcı değişikliği kaynakJSON'a işleyin veya farklıUID ile dashboard kopyası kullanın.

## Kabul ve yedek

`systemctl is-active` yanında exporter/Prometheushealth, Grafana `/api/health`, datasourcehealth, `wirewall_up=1`,scrapeup1,realLinux/nativeenforce/v9,19panel kontrol edilir. `ss -lntp` ile loopback binding doğrulanır. `/metrics` için `promtool check metrics` kullanılır. Token/password/cookie/CSRF değerleri çıktılara kaydedilmez. Root'tan özel Unix socket kullanılabilir.

Servis restart'ta Prometheus aynı zaman aralığının örneklerini korumalıdır. Grafana dashboard ve kullanıcı verisi `/var/lib/grafana`; Prometheus `/var/lib/wirewall-prometheus`. Tutarlı yedek için ilgili izleme servislerini durdurup veriyi root özel yedek dizinine alın. Grafana secrets/config ayrıca gerekir; bu yedekleri teslim paketine koymayın. SQLite olay geçmişi root `/var/lib/wirewall` state'idir; kendi backupAPI/durdurulmuşservis yöntemi uygulanır. TSDB retention ile SQLite olay retention birbirinden ayrıdır.

## Ayrı kaldırma

```bash
systemctl disable --now wirewall-metrics wirewall-prometheus grafana-server
rm -- /etc/systemd/system/wirewall-metrics.service /etc/systemd/system/wirewall-prometheus.service
systemctl daemon-reload
```

Bu işlem çekirdek firewall'ı/nft politikasını değiştirmez. Vendor Grafana başka amaçla kullanılmıyorsa paket apt remove ile kaldırılabilir. İzleme config/secrets/state, sadece artık gerekmediği ve yedeklendiği doğrulandıktan sonra adları açıkça seçilerek silinir. APTrepo/anahtarı başka paket kullanmıyorsa yalnız projeye ait dosyalar kaldırılır. Başka kullanıcı veya servis dizinlerine dokunulmaz. [Kabul raporu](TESTING.md).
