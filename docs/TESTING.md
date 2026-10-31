# Doğrulama ve ölçülmüş sonuçlar

Bu belge 30 Ekim 2026 gerçek Linux deneylerini, sentetik laboratuvarı ve derleme/ABI kapılarını ayırır. 31 Ekim GitHub hazırlığında modül yolu güncellendi ve taşınabilir testler tekrar çalıştırıldı; tarihsel ağ ölçümleri yeni commit üzerinde tekrar ölçülmüş gibi gösterilmez.

## Ortam ve kabul katmanları

Gerçek hedef Ubuntu 22.04.5 LTS, Linux 5.15.0-46-generic, x86_64 KVM, 4 vCPU, yaklaşık 16 GiB RAM, virtio_net, MTU1500 ve bir combined queue. Native sürücü XDP, generic XDP, stateful nft ve baseline karşılaştırıldı.

| Kontrol | Ne gösterir? | Ne göstermez? |
|---|---|---|
| Windows/Linux Go test/vet | Taşınabilir kodun davranışı ve derleme | Kernel'e XDP yüklendiğini |
| BPF ELF/BTF ABI | Map/struct boyutu ve offset uyumu | Verifier kabulünü |
| BPF_PROG_TEST_RUN | Gerçek kernel içinde paket korpusu | Fiziksel NIC kapasitesini |
| Namespace/veth | Gerçek servis, izin/ret ve süreç kurtarma | Upstream DDoS kapasitesini |
| Gerçek uplink | Native attach, yeni SSH, restart/reboot | Bütün sürücü/kernel kombinasyonlarını |
| Sentetik lab/Playwright | Panel, filtre ve rapor akışları | Gerçek saldırı veya paket üretimini |

Kernel kapısı IPv4/IPv6/VLAN, bozuk paket/bayrak/uzunluk, fragment/extension, dar yönetim istisnası, engel TTL, toplam/kaynak paket ve byte bütçesi, policy generation/reader ve trafik sayaçlarını kapsar. Namespace testleri izinli/yasak gerçek HTTP servisini, farklı state diziniyle ikinci agent reddini, SIGKILL sonrası bağımsız 90s geri almayı ve resume-confirmed davranışını doğruladı.

## Tekrar çalıştırma

Önce `bash scripts/linux/build.sh`, Go test/vet ve kernel/namespace/recovery testleri geçmelidir. Benchmark yalnız geçici private namespace/veth kullanır; host uplink'e trafik göndermez, default route eklemez. Sabit istemci10.203.0.1, sunucu10.203.0.2 ve UDP9000/9001 kullanılır.

```bash
sudo -E env WIREWALL_ALLOW_NETNS_BENCHMARK=1 \
  bash scripts/linux/benchmark.sh \
  --include-native --duration 5 --warmup 1 --repetitions 5 \
  --legitimate-rate 500 --background-rate 5000 \
  --payload-bytes 64 --rule-count 1
```

Yeni `--output` dizini kullanılır, eski sonuç üzerine yazılmaz. `--payload-bytes`32..1400 uygulama UDP byte sayısıdır; `--rule-count`1..64 sıralı XDP kuralıdır. Son DROP önündeki padding kuralları eşleşmeyen kaynaktan gelir. Nft host politikası bu sayıyla çoğalmaz;64 eşdeğer nft ACL karşılaştırması yapılmadı.

Her run taze iki namespace kullanır, mod sırası döndürülür. Echo readiness politika öncesi UDP probe göndermeden doğrulanır; ısınma da kurulu filtreyle yapılır. Önceki modun conntrack oturumu taşınmaz. Mevcut otomatik guard onayı yalnız atılabilir benchmark namespace'i içindir; gerçek VDS'de yeni SSH kontrolünün yerine geçmez.

## 100-run matris ve ek 20-run tekrar

Her konfigürasyon dört mod × beş tekrar,1sısınma ve5sölçüm. İstenen oran500meşru/5000arka planPPS. Ham kayıtlarda gerçek offeredPPS, gönderilen/benzersiz yanıtlanan paket, hata, pacing reset, RTT p50/p95, ayrı process ve paylaşılan host CPU sayaçları tutulur. Başarı paydası başarılı sendto sayısıdır; nearest-rank RTT yalnız yanıtlanan örneklerden hesaplanır.

| Payload / XDP kural | Baseline p95 medyan ms | Nft ms | Generic ms | Native ms |
|---|---:|---:|---:|---:|
|64 /1|0,058751|0,068869|0,072758|0,073889|
|512 /1|0,060626|0,071595|0,071775|0,073210|
|1400 /1|0,061957|0,068289|0,072296|0,073439|
|64 /16|0,062208|0,072737|0,070053|0,074119|
|64 /64|0,064162|0,070203|0,073589|0,076214|

Nft1.0.2 JSON'un tablo comment'ini atlaması için text sahiplik doğrulamasını koruyan uyumluluk düzeltmesinden sonra64byte/1kural ile ek20run yapıldı:

| Mod | p95 medyan ms | min–max ms |
|---|---:|---:|
|baseline|0,057316|0,054814–0,057708|
|nft|0,064611|0,063720–0,067969|
|generic|0,064282|0,062329–0,067416|
|native|0,066835|0,063660–0,070002|

Bütün120run: meşru echo%100; baseline arka plan%100; filtreli modlar arka plan%0; gönderme hatası0. Bu sabit düşük yükte native hız üstünlüğü gösterilmedi. [Makine okunabilir sonuçlar](benchmarks/results.json) min/max, offeredPPS ve paylaşılan CPU değerlerini de taşır.

Ana100run kontrol düzlemi nft sayaçlarını unavailable gösteriyordu, paket filtresi çalışıyordu. Ek20run düzeltmeden sonra yapıldı. Daha sonraki Grafana/history Go eklemeleriyle benchmark tekrar ölçülmedi; C/BPF obje aynı kaldı. BPF SHA256 `87459e94bb0c81c7f34fe6c7048df6fbe82efceff0f350a281dd1d5dbebeb92f`. Paylaşılan VM CPU'su yalnız firewall CPU'su değildir; Python sender, echo ve diğer servisler de dahil olabilir.

## Native süreklilik ve gerçek reboot

`scripts/linux/soak-netns.py` tek native firewall örneğini64kural/512byte ile10×30s açık tuttu.303,90s toplam sürede150.000meşru paket gönderildi/yanıtlandı,1.499.982arka plan gönderildi/yanıt0. Her tur attachednative/pendingfalse, eventDrops0. XDP son sayacı1.650.013received/1.499.985drop oldu; echo ve XDP gözlem noktası farklı olduğundan birebir toplam eşitliği iddia edilmez.

Gerçek VDS'de native/enforce/v9 kalıcı geçişi, aynı onaylı dağıtımın servis restart'ı ve kullanıcı onaylı reboot geçti. BootID değişti, native otomatik bağlandı, pendingfalse kaldı, yeni SSH + ayrı freshSSH ve panelhealth geçti. Süreli fallback çalışmadı ve test unit'leri kaldırıldı. Başka servisin varlığı reboot öncesi kullanıcıya bildirildi. Sunucu adresi, hostname, yönetim CIDR'i ve özel yedekler kamuya açık sonuçlara dahil edilmedi.

## Panel, olay geçmişi ve Grafana

Ayrı sentetik lab13/13 Playwright: auth, kural/engel, export, mobil/bağlantı hatası, geçmiş filtre/cursor/CSV, HTML escaping ve hata durumunda eski özeti temizleme. Canlı kabulde gerçek geçmiş filtre/sayfalama/CSV, desktop1536×1024 ve mobil390×844 taşmasız görünüm doğrulandı.100000SQLite sentetik fixture'ın aggregate sorgusu gerçek VDS'de780,966ms sürdü; bu ağkapasite ölçümü değildir.

Grafana OSS13.3.0 ve Prometheus3.15.1 kuruldu.19panel,21veri ifadesi, datasourcehealth ve gerçek native/enforce/simulated0 GUI kabulü geçti. Prometheus restart öncesi/sonrası aynı sabit geçmiş aralığındaki120örnek korundu; Grafana restart databaseok döndürdü. Tutma sınırı30gün/2GB'dir; henüz30gün geçmiş oluştuğu iddia edilmez.

Grafana13.3 ilk kullanıcı sayfa-geçmişi GET404'ü vendor kaynakta boşkaynak yolu olarak tanımlıdır. Kabulde yalnız bu endpoint için dar istisna kullanıldı; diğer console/JS/panel hataları için genel istisna yok. [UserStorage kaynak kodu](https://github.com/grafana/grafana/blob/v13.3.0/packages/grafana-runtime/src/utils/userStorage.tsx), [PageHistorySrv](https://github.com/grafana/grafana/blob/v13.3.0/public/app/core/services/pageHistory/pageHistorySrv.ts).

## Yorum sınırları

Namespace/veth, fiziksel NIC veya upstream kapasite testi değildir. Mpps/line-rate, tam çokçekirdek baskısı, günler süren soak, globalIPv6 WAN ve gerçekARM64 kernel test edilmedi. ARM64 crossbuild derleme kanıtıdır. Örnek olay sayısı saldırı/bağlantı toplamı değildir. Kamuya açık depoda özetler ve tekrar üretme harness'i bulunur; canlı state ve özel kabul logları paylaşılmaz.
