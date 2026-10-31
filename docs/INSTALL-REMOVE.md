# Ubuntu kurulum, güncelleme ve kaldırma

Hedef: Ubuntu 22.04+, x86_64. Gerçek sonuçların sınırı test raporlarındadır. Root SSH ve sağlayıcı konsolu gereklidir. Paket/build komutları yeni ağ politikası yüklemez. Bu rehberdeki örnek yönetim adresini kendi genel IP'nizle değiştirin.

## Temiz kurulum

1. `scripts/linux/preflight.sh eth0` ile arayüz, başka XDP ve nft tablolarını okuyun. Başka yöneticinin programını kaldırmayın. Root olmayan panel kullanıcısı oluşturun:

```bash
sudo apt-get update
sudo apt-get install -y clang llvm gcc libbpf-dev linux-libc-dev iproute2 nftables conntrack python3 curl ethtool
sudo useradd --system --home-dir /var/lib/wirewall-web --shell /usr/sbin/nologin wirewall
```

Kullanıcı zaten varsa yeniden oluşturmayın. `go.mod` ile uyumlu resmi Go toolchain ve frontend build için Node/npm kullanın. Proje SDK indirme lisanslarını dağıtmaz.

2. Kaynakları `/opt/wirewall` altına açın. Web için `npm --prefix web ci && npm --prefix web run build`; Linux için `bash scripts/linux/build.sh` çalıştırın. Derleme ağ arayüzüne bağlanmaz.
3. `go test -count=1 ./...`, `go vet ./...`, `scripts/linux/test-kernel.sh`, `scripts/linux/test-netns.sh` ve `scripts/linux/test-recovery.sh` geçmelidir. Namespace testleri geçici veth kullanır. Kernel testi arayüze program bağlamaz.
4. `/etc/wirewall/policy.json` dosyasını `deploy/policy.example.json` temelinde oluşturun. Gerçek yönetim CIDR'i, SSH portu ve arayüzü girin; önce `mode: observe` tercih edin. Native destek yoksa açıkça generic seçin; sessiz fallback yapılmaz. `bin/wirewall validate --policy /etc/wirewall/policy.json` ile doğrulayın.

```bash
sudo install -d -o root -g wirewall -m 0750 /etc/wirewall /run/wirewall
sudo install -d -o root -g wirewall -m 0700 /var/lib/wirewall
sudo install -d -o wirewall -g wirewall -m 0700 /var/lib/wirewall-web
sudo chown root:wirewall /etc/wirewall/policy.json
sudo chmod 0640 /etc/wirewall/policy.json
sudo install -m 0644 deploy/wirewall.service /etc/systemd/system/wirewall.service
sudo install -m 0644 deploy/wirewall-web.service /etc/systemd/system/wirewall-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now wirewall wirewall-web
```

5. İlk başlangıçta 90 saniyelik geri alma vardır. **Yeni, multiplex kullanmayan SSH bağlantısını açın**, snapshot'ta attached/mod/arayüz/sağlığı kontrol edin; sonra panelde aktivasyonu onaylayın. Yalnız açık kalan eski SSH veya HTTP health yeterli değildir. Süre aşılırsa guard kayıtlarını silmeyin; kurtarmayı inceleyin.
6. Panel loopback 9876'da, `ssh -N -L 9880:127.0.0.1:9876 root@SUNUCU` tüneliyle yerel 9880'den açılır. Anahtar `/var/lib/wirewall-web/operator.token` dosyasındadır. Değeri kaynaklara veya rapora koymayın.

## Onaylı politikanın yeniden başlaması

Systemd agent `--resume-confirmed` kullanır. İlk onay root state içinde özel `confirmed-startup.json` üretir. Yalnız aynı politika sürümü/içeriği, süresi dolmamış engeller, arayüz MAC/IP adresleri ve çalışan binary/BPF SHA256 değerleri eşleşirse yeniden başlangıç önceki onayın devamı sayılır. **Yeni bir guard otomatik onaylanmaz.** Değişiklik veya eksik/bozuk kayıt normal 90 saniyelik başlangıcı gerektirir. Süresi doğal dolan ban yenilenmez. Bu seçenek olmadan her başlangıç onay gerektirir.

Yeni policy/ban işlemleri her zaman watchdog kullanır. Pending/başarısız kurtarma kayıtları resume seçeneğiyle geçilemez. IP değişimi, program güncellemesi ve arayüz değişimi gözetimli yapılır. Ani güç kaybı pending guard bırakırsa otomatik tekrar yerine konsoldan kurtarma gerekir; yeni politikayı sessizce kalıcılaştırmayız.

## Güncelleme ve native moda geçiş

Yeni sürümü ayrı dizinde derleyip kernel/namespace testlerini bitirin. SQLite canlı dosyasını `cp` ile kopyalamayın; SQLite backup API veya durdurulmuş servis yedeği kullanın. Dosya, politika ve state yedekleri 0700/0600 ile özel tutulur.

Agent/web durdurulmadan önce bağımsız süreli fallback kurun; fallback yalnız WireWall'ın önceki binary/BPF/politikasını geri getirip kendi servislerini başlatmalıdır. Yeni binary/BPF aynı dosya adında atomik rename ile yayınlanır; çalışan dosyanın üzerine yazmayın. Servisleri başlatın; **yeni SSH bağlantısı ve sağlıklı snapshot sonrası** aktivasyonu onaylayıp fallback'i iptal edin. Başka nft tablosu veya ağ ayarı değiştirilmez.

Native için güncel kayıtlı politikanın tam kopyasında yalnız `xdpMode` değiştirin. Kontrollü bir defalık `agent --replace-policy --policy ...` başlangıcı sürümü artırır. Kalıcı unit'e `--replace-policy` eklemeyin: bu, panel politikasının her açılışta üzerine yazılmasına neden olur. Politika dosyası normalde yalnız bootstrap'tir.

## Kaldırma

Önce sağlayıcı konsolu ve bağımsız SSH hazır olsun; politika/state yedeği alın. Pending değişiklik varsa önce kendi guard'ının tamamlanmasını bekleyin veya onay/kurtarmasını bitirin.

```bash
sudo systemctl disable --now wirewall-web wirewall
```

Normal agent kapanışı kendi XDP linkini bırakır. `ip -j link show dev eth0` ile doğrulayın; başka program varsa elle `xdp off` kullanmayın. Watchdog/sahiplik çözülmeden dosyaları silmeyin. Onaylı nft tablosu servis kapanınca korunur. Root konsolunda yalnız aşağıdaki tabloyu okuyun:

```bash
sudo nft list table inet wirewall
```

Tablonun `comment "managed-by-wirewall"` taşıdığını, çalışan WireWall/guard olmadığını doğruladıktan sonra yalnız bu tablo kaldırılır:

```bash
sudo nft delete table inet wirewall
sudo rm -- /etc/systemd/system/wirewall.service /etc/systemd/system/wirewall-web.service
sudo systemctl daemon-reload
```

`flush ruleset` kullanılmaz. Yeni SSH bağlantısını doğrulayın. `/opt/wirewall`, `/etc/wirewall`, `/var/lib/wirewall` ve `/var/lib/wirewall-web` veri/yedeklerini ancak artık gerekmediğinden emin olduktan sonra kaldırın. Paylaşılan Go/Clang/nftables araçları veya kullanıcıyı başka servis kullanıyorsa silmeyin. İzleme kurulmuşsa onun ayrı kaldırma adımları da uygulanır. Operatör anahtarı ve audit kayıtları yedekler içinde gizli veri sayılır.

## Kurtarma

İlgili `DATA/guards/ID.json` ile `.outcome/.rolledback/.failed/.log` birlikte incelenir. Kayıtlar otomatik silinmez. Sağlayıcı konsolundan beklenen politika, sahip olunan XDP program/link ID ve `inet wirewall` doğrulanır. Çalışan watchdog'un kurtarmasını bekleyin. Başka programı kaldırmayın; çözülmemiş kaydı sırf servis başlasın diye silmeyin. Detaylar: [Linux rehberi](LINUX.md).

## İzleme bileşenleri

Gerçek kurulum, yeniden kurulum ve ayrı kaldırma adımları [MONITORING.md](MONITORING.md) içindedir. Çekirdek firewall kaldırılacaksa önce `wirewall-metrics` durdurulur; izleme verisini koruma/silme kararı ayrıca verilir.
