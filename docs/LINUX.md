# Ubuntu ve gerçek XDP veri yolu

Bu belge Linux derleme, test ve aktivasyon akışını açıklar. Ölçülmüş sonuçlar [test raporundadır](TESTING.md). Windows cross-build veya sentetik laboratuvar gerçek kernel/NIC deneyi olarak sunulmaz.

## Çalışma modeli

`NIC → XDP erken ACL/limiter → XDP_PASS → conntrack/nftables → servis`

- XDP yalnız ingress yönündedir. Gerçek TCP/UDP durum takibi nftables/conntrack katmanındadır.
- Observe, yalnız XDP'nin önerdiği ret kararlarını geçirir; host servis politikasını devre dışı bırakmaz.
- Enforce modunda IPv4 options, IP fragmentleri, IPv6 extension/jumbogram ve desteklenmeyen IP protokolleri **complex_packet nedeniyle düşürülür**. Host service politikası erken ACL'nin tam kopyası olmadığı için bunları yalnız host katmanına geçirmek IP/CIDR/port kurallarını atlatabilirdi. Observe modunda would-drop sayılır ve geçer. Bu, geçerli bazı ağ trafiğini de engelleyen açık bir uyumluluk kısıtıdır. Basit IPv4/IPv6 TCP/UDP/ICMP ve normal Neighbor Discovery desteklenir; genel fragment/extension desteği tamamlandı diye sunulmaz.
- XDP'deki IP engeli mevcut akış paketlerini de keser. Host servis iznini kaldırmak established oturumları aynı şekilde sonlandırmaz.
- Kaynak tablosu 8.192 girdidir. Dolarsa kaynak ayrıntı limiti atlanır, kuralın aggregate bütçesi korunur ve capacity_fallback artar. Bu davranış panelde görünür; kaynak IP kimlik doğrulaması değildir.
- Kernel olayları 1/64 örneklenir ve ayrıca 64 olay/saniye ile sınırlandırılır. PASS/DROP ve neden sayaçları örneklenmez. Event sayısı paket veya bağlantı sayısı olarak kullanılmaz.
- Eşzamanlı politika geçişi ARRAY_OF_MAPS içindeki tek policy-map referansını değiştirir. XDP+nftables birlikte tek global atomik işlem değildir. Ban-only set güncellemesi de bütün-set atomiklik iddiası taşımaz.
- Eski politika okuyucularının kullandığı ban/limit kayıtları hemen silinmez. XDP, politika map'ini okumadan önce per-CPU aktif okuyucu sayacını atomik artırır ve tüm çıkışlarda azaltır. Yayın sonrasında bütün CPU sayaçlarının sıfır gözlenmesi, eski referansı almış işlerin tamamlandığını gösterir; CPU'ların aynı anda okunması gerekmez çünkü yeni başlayan işler yalnız yeni map referansını alabilir. Yoğun bir CPU varsa temizlik ertelenir. En fazla sekiz emekli jenerasyon tutulur; sınırda yeni aktivasyon, eski durumu silmek yerine reddedilir. Bu mekanizmanın gerçek kernel davranışı opt-in testle doğrulanmalıdır.
- Shared token bucket, farklı CPU'lardaki paketler kilide ters sırada girdiğinde refill zamanını geriye taşımaz. Per-CPU istatistik sayaçları host genelinde ayrı limitler olarak kullanılmaz.
- Normal dağıtımda gerçek veri yolu root `agent` sürecinde, web paneli düşük yetkili `serve --backend remote` sürecindedir. Root agent TCP portu açmaz; özel Unix socket izinleri kontrol sınırıdır. `serve --backend xdp` yalnız izole tanılama/namespace testleri için tek süreçli yoldur. Bu ayrım gerçek Ubuntu VDS'de systemd servisleri, kullanıcı/dosya/socket izinleri ve restart ile doğrulandı.

## Derleme

Ubuntu Server amd64 veya arm64 hedeflenir. Gerçek derleme/verifier/izole ağ doğrulaması Ubuntu 22.04.5 LTS, Linux 5.15.0-46-generic, amd64 ve Clang 14 üzerinde yapıldı. ARM64 için şu aşamada cross-build ve ELF/BTF ABI kontrolü vardır; gerçek ARM64 kernel testi yapılmadı. Native XDP sürücü desteğine bağlıdır; generic mod sessiz fallback olarak seçilmez, açıkça yapılandırılır.

Gerekli paketler: clang, llvm, gcc, libbpf-dev, linux-libc-dev, iproute2, nftables, conntrack, python3, curl ve desteklenen Go toolchain. Web paketini derlemek için Node.js/npm gerekir. Kurulum bu projedeki hiçbir build script'inde otomatik yapılmaz.

```bash
bash scripts/linux/build.sh
go test ./...
# İstenirse frontend kendi package.json scriptleriyle derlenir.
```

`build.sh` yalnız dosya üretir. Ağ arayüzüne attach yapmaz ve firewall uygulamaz. BPF objesi `bpf/wirewall_bpfel.o`, sunucu `bin/wirewall` olur. C ve Go ortak veri yapılarında boyut kontrolleri bulunur.

Clang14 uyumluluğu için iç `policy_template` ARRAY haritası `value_size=sizeof(ww_policy)` kullanır; `.rodata` içindeki kullanılmayan ABI sentinel'i somut struct BTF/offset denetimini korur. Böylece nested pointer'ın eksik forward type'a indirgenmesi harita yüklemesini bozmaz. Aktif politika `policies` map-in-map üzerinden yayımlanır. IPv4/IPv6/UDP wire uzunlukları compiler barrier ve16-bit maskeyle sınırlandırılır. Politika işleme ve örneklenmeyen sınıflandırma, Linux5.15 verifier'ın state sınırını aşmamak için bağımsız global BPF fonksiyonlarıdır; sınıflandırma ayrıca parse eder, maliyeti ölçümlere dahildir. Bu yollar ABI ve gerçek paket korpusu testleriyle kontrol edilir.

Windows'ta VM/WSL olmadan aynı C kaynağını derlemek için `python scripts/dev/compile_bpf_windows.py` kullanılabilir. Resmi Zig arşivi ve sabitlenmiş libbpf başlıkları checksum ile doğrulanır, araçlar yalnız `.tools/` içine alınır. Önbellek hazırsa `--offline` ağ kullanmaz. `--arch arm64 --output bpf/wirewall_arm64_bpfel.o` ikinci hedefi üretir. Manifest kaynak, ortak header ve object SHA-256 değerlerini içerir. `go test ./internal/dataplane -run TestCompiledObjectABI` var olan object'in gerçek ELF/BTF map ve struct boyutlarını syscall yapmadan kontrol eder; explicit `WIREWALL_BPF_OBJECT` yolu eksikse hata verir. Bu kapı C derleme/ABI kontrolüdür, Linux verifier veya paket işleme başarısı değildir.

Byte bütçelerinde `bps` ve `sourceBps` **byte/s**, `byteBurst` ve `sourceByteBurst` **byte** birimindedir; panel trafik metriği `metrics.bps` ise bit/s'dir. Byte sınırları zorunlu aggregate PPS sınırına ek olarak çalışır; kaynak byte limiti kaynak PPS limiti olmadan da etkin olabilir. Her bucket içinde paket ve byte kredisi tek kilit altında birlikte tüketilir. Kaynakta daha sonra reddedilen paket aggregate offered-traffic bütçesini tüketmiş sayılır. Hesaplanan uzunluk IP paket uzunluğudur; Ethernet/hat overhead'i dahil değildir. Kaynak tablosu baskısında kaynak byte limiti de aggregate PPS/byte bütçesi korunarak fallback'e geçer.

En fazla sekiz emekli nesil bir üst sınırdır; fiziksel ban/source map kapasitesi dolarsa aktivasyon bu sınıra ulaşmadan da güvenli biçimde reddedilebilir. Aktif politika neslinin kaynak tablosunda agresif idle/LRU silme yapılmaz; bu, eşzamanlı bir kaynağın burst durumunu yanlışlıkla sıfırlamayı önler, fakat uzun yaşayan politika neslinde kaynak ayrıntı kapasitesi dolu kalabilir. Aggregate bütçe bu durumda da geçerlidir.

## Önce arayüze bağlanmayan kernel testleri

```bash
sudo -E bash scripts/linux/test-kernel.sh
```

Bu testler derlenmiş C programını BPF_PROG_TEST_RUN ile kernel içinde çalıştırır. Kural eşleşmesi, VLAN, IPv4/IPv6 kısa/bozuk başlık ve uzunlukları, çelişkili TCP bayrakları, fragment/extension ile ACL atlama girişimi, dar yönetim istisnası, observe ve aggregate burst davranışını kontrol eder. Ban TTL testi, kernel map kaydı yerinde dururken deadline'ı geçirerek veri yolunun userspace temizleyiciye ihtiyaç duymadığını sınar. Reader sayacının tüm çıkışlarda sıfırlanması ve emekli jenerasyon sınırı/temizliği ayrıca sınanır. Sürücü/NIC ve nftables entegrasyon testinin yerine geçmez.

## İzole namespace entegrasyonu

```bash
sudo -E bash scripts/linux/test-netns.sh
```

Script iki ayrı network namespace ve veth çifti oluşturur. Önce 8080 ve 8081'deki iki gerçek HTTP servisine erişildiğini doğrular. Daha sonra yalnız server namespace içinde generic XDP ve host politikası başlatır; API hazır olunca aktivasyonu doğrular, 8080'in çalıştığını ve 8081 için XDP rule_drop sayacının arttığını kontrol eder. Host'un gerçek uplink arayüzünü kullanmaz. Oluşturduğu namespace ve geçici dosyaları temizler.

Bu smoke test bütün protokol/donanım matrisi değildir. Native sürücü, gerçek SSH erişimi, IPv6 parçalama, çok çekirdek eşzamanlılığı, tablo baskısı, kernel OOM/conntrack basıncı ve uzun süreli performans ayrı kapılardır. Bu VDS'deki kısa native bağlantı/yeni SSH/paket filtresi deneyi [native test raporunda](TESTING.md) kayıtlıdır; kapasite/uzun süreli yük doğrulaması yerine geçmez.

Bağımsız geri almayı ve crash sonrası yeniden başlatma kilidini gerçek kernel/nftables ile ayrıca sınamak için:

```bash
sudo -E bash scripts/linux/test-recovery.sh
```

Bu deney yalnız kendi geçici namespace/veth kaynaklarını kullanır. XDP ret sayacı ve açık aktivasyon süresi doğrulanır; ana süreç SIGKILL ile kapatılır, farklı veri diziniyle ikinci başlangıcın engellendiği kontrol edilir. Onay verilmeyen 90 saniyelik süre sonunda watchdog'un nft/SQLite durumunu geri alması, XDP'nin ayrılması, iki HTTP servisine yeniden erişim ve sahipliğin bırakılması doğrulanır. Normalde yaklaşık 90 saniye sürer; kurtarma için ayrıca sınırlı bekleme vardır. Operatör anahtarı Python belleğinde kalır; shell tracing ile çalıştırılmaz.

## Gerçek VM/VDS aktivasyonu

Bu adımlar kullanıcı gerçek ortamı seçip kurulumu onayladığında uygulanır. Bu proje için VDS aşaması onaylandı; güncel sonuçlar ve bağlantı engelleri `docs/STATUS.md` dosyasındadır.

SSH sunucu anahtarı kayıtla uyuşmazsa doğrulama kapatılmaz ve kayıt sessizce değiştirilmez. Sağlayıcı panel konsolunda `ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub` çıktısı kontrol edilir; yalnız doğrulanmış anahtar yeni kayıt olarak alınır. Parola komut satırına, kaynaklara veya aktarım paketine yazılmaz.

1. Sağlayıcı/VM konsolu ve mevcut firewall durumu hazırlanır. `deploy/policy.example.json` içindeki **dokümantasyon IP'si olan 192.0.2.10/32 kullanılmaz**; gerçek yönetim IP/ağı, SSH portu ve arayüz adı girilir.
2. `bash scripts/linux/preflight.sh ARAYUZ` yalnız bilgi okur. Arayüzde başka XDP programı varsa uygulama üzerine yazmayı reddeder.
3. Derleme ve kernel testleri geçer. Host politikası yalnız seçili arayüzün local input yolunu yönetir; output/forward ve diğer tabloları silmez. SSH yönetim portu genel servis listesinde olsa bile yalnız yönetim CIDR istisnasından açılır.
4. Düşük yetkili `wirewall` sistem kullanıcısı/grubu ve gerekli dosyalar hazırlanır. Ayrı süreçlerle ilk foreground çalıştırma için socket dizini root sahibi, wirewall grubu ve tam 0750 izinli olmalıdır:

```bash
sudo install -d -o root -g wirewall -m 0750 /run/wirewall
sudo bin/wirewall agent \
  --policy /etc/wirewall/policy.json \
  --object ./bpf/wirewall_bpfel.o --data /var/lib/wirewall \
  --socket /run/wirewall/control.sock --confirm-network-changes
# Ayrı terminalde, root olmayan web süreci:
sudo -u wirewall bin/wirewall serve --backend remote \
  --socket /run/wirewall/control.sock --data /var/lib/wirewall-web \
  --listen 127.0.0.1:9876 --web ./web/dist
```

5. Bağımsız 90 saniyelik geri alma etkinleşir. Yeni bir SSH oturumuyla erişim ve servis kontrol edilir; bu bağlantıda `-o ControlMaster=no -o ControlPath=none` kullanılarak mevcut SSH bağlantısının paylaşılması önlenir. Ardından paneldeki aktivasyon onayı verilir; doğrulanmayan aktivasyon kendiliğinden geri alınır. Tek mevcut SSH oturumunun açık kalması veya yalnız HTTP health yanıtı yeterli kanıt değildir. Yetkili snapshot'ta XDP backend'i, beklenen mod, bağlı arayüz ve hata durumu da kontrol edilir.
6. Panel erişimi için SSH tüneli kullanılır. Panel token'i ayrı web veri dizinindeki `/var/lib/wirewall-web/operator.token` dosyasında saklanır; root agent'e taşınmaz ve Git'e eklenmez.

`deploy/wirewall.service` root agent, `deploy/wirewall-web.service` düşük yetkili panel için örnek systemd birimleridir; otomatik kurucu değildir. Kullanıcı/grup, dosya yolları ve socket izinleri gözden geçirilmeden etkinleştirilmez. Agent için `KillMode=process` bağımsız watchdog'un yaşamını korur; `Restart=no` doğrulanmamış aktivasyonun tekrar tekrar uygulanmasını önler. Kernel CAP_BPF/CAP_NET_ADMIN desteği hedef ortamda doğrulanır. Normal socket kapanışı kendi socket dosyasını temizler; crash'ten kalan dosya varsa uygulama sessizce üzerine yazmaz, aktif süreç olmadığı doğrulanıp yalnız o dosya operatör tarafından temizlenir.

`--policy` ilk bootstrap kaynağıdır. Panelden kaydedilen politika yeniden başlatmada korunur. Dosyayı bilerek yeniden yüklemek için `--replace-policy` gerekir; sürüm artırılır. Eski bootstrap dosyasının panel değişikliklerini sessizce silmesine izin verilmez.

## Kurtarma ve kapanış

- Gerçek `agent` veya `serve --backend xdp` başlarken, SQLite açılmadan önce ağ namespace'ine ait tek WireWall sahiplik soketi alınır. Bu bir Linux abstract Unix socket'idir; dosya silerek kaldırılan bir kilit değildir. Aynı namespace'te farklı `--data` dizini seçmek ikinci firewall başlatmaya izin vermez. Web proxy ve sentetik laboratuvar bu ağ kilidini almaz.
- Bağımsız watchdog aynı soket tanıtıcısını miras alır. Ana süreç çökse bile watchdog kurtarmayı tamamlayana kadar yeni agent başlayamaz. Watchdog onayla sona erse de çalışan agent kilidi tutmaya devam eder. Bütün sahipler kapanınca kernel kilidi bırakır; otomatik olarak ağ kuralı veya kurtarma kaydı silinmez.
- Başlangıçta `another WireWall daemon or rollback watchdog still owns this network namespace` görülürse önce mevcut süreç/geri almanın bitmesi beklenir. `unresolved rollback record` görülürse `DATA/guards/` altındaki ilgili JSON ve yanındaki `.log`, `.failed`, `.outcome`, `.rolledback` kayıtları incelenir. Yalnız onaylanmış veya bütün kurtarması tamamlanmış kayıtlar otomatik olarak yeniden başlatmaya izin verir. Başarısız/eksik/bozuk kayıtlar elle kurtarma gerektirir: sağlayıcı konsolunda projeye ait nft/XDP sahipliği ve kalıcı politika doğrulanıp kurtarma tamamlanmadan kayıtlar silinmez veya süreç zorla tekrar başlatılmaz.
- Geri alma yalnız `inet wirewall` tablosunu yönetir. Önceden aynı isimli sahipsiz bir tablo varsa ownership marker kontrolü nedeniyle uygulama reddedilir.
- Watchdog kernel program ve BPF link kimliklerini doğrular; başka yöneticinin sonradan bağladığı programa dokunmaz.
- Normal process kapanışı kendi BPF link referansını kapatır; başka XDP programını kaldırmaz. Onaylı host politikası kapanıştan sonra yerinde kalabilir; bu davranış servis ve kaldırma rehberinde açıkça dikkate alınmalıdır.
- Kural veya dosya kaydı başarısızlığında açık Restore yolu eski politikaya döner. Kernel olmayan platformlarda gerçek XDP backend'i açık hata verir.
- XDP_DROP paketleri normal tcpdump'da görünmeyebilir. Doğrulama için kernel action sayaçları, xdpdump ve istemci sonuçları birlikte değerlendirilir.

## Teknik kaynaklar

- [Go eBPF](https://ebpf-go.dev/)
- [Kernel BPF testleri](https://docs.kernel.org/bpf/bpf_prog_run.html)
- [Kernel map türleri ve eşzamanlılık](https://docs.kernel.org/bpf/map_hash.html)
- [nftables atomik rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)
- [Conntrack ayarları](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)

## Onaylı yeniden başlangıç ve izleme

Unit --resume-confirmed kullanır. Politika/bans, NIC MAC/IP ve binary/BPF SHA256 aynı önceki açık operatör onayıyla eşleşirse yeni başlangıç bu onayın devamıdır. Yeni/pending/bozuk guard otomatik onaylanmaz. Native restart ve gerçek VDS reboot kabulü30Ekim raporundadır. İlk/yeni dağıtım ve ağ değişikliği yine90s watchdog ve yeni bağımsızSSH gerektirir.

[Gerçek120run ve reboot sonuçları](TESTING.md), [Grafana kurulumu](MONITORING.md), [izleme/kalıcı geçmiş kabulü](TESTING.md). ARM64 crossbuild gerçekARM64 kernel testi değildir.
