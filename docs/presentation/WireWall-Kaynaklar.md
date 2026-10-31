# WireWall sunum kaynakları

Bu kaynakça, [final sunumunun](WireWall-Final.pptx) ve [PDF görünümünün](WireWall-Final.pdf) son altı slaytındaki başvuruları açıklar. Numaralar sunumla aynıdır. Son bağlantı kontrolü: **31 Ekim 2026**.

Teknik belgeler uygulama ve doğrulama sırasında başvuru amacıyla kullanıldı. Açık kaynak projeler tasarım araştırmasında, ticari ürünler ise üretici belgeleri üzerinden incelendi. Listelenen araştırma ürünleri WireWall dağıtımına eklenmedi ve bunlarla ürün karşılaştırma testi yapılmadı. Kullanılan bağımlılıkların sürümleri ve lisans bildirimleri [bağımlılık belgesindedir](../DEPENDENCIES.md).

## Linux ve eBPF belgeleri

1. [Linux: XDP kararları ve paket bağlamı](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h) — XDP program türünün, paket bağlamının ve geçirme/düşürme kararlarının çekirdek tanımlarını açıklar.
2. [Linux: eBPF doğrulayıcısı](https://docs.kernel.org/bpf/verifier.html) — Paket sınırları ile bellek erişiminin nasıl denetlendiğini açıklar. Politikanın doğruluğu ayrıca test edilir.
3. [Linux: karma, per-CPU ve LRU haritalar](https://docs.kernel.org/bpf/map_hash.html) — Harita kapasitesi ile eşzamanlı erişimi açıklar. WireWall kaynak tablosunda LRU ile kayıt tahliyesi kullanmaz.
4. [Linux: harita içinde harita](https://docs.kernel.org/bpf/map_of_maps.html) — Politika neslinin değiştirilmesinde kullanılan ARRAY_OF_MAPS yapısının davranışını açıklar.
5. [Linux: BPF_PROG_RUN ve BPF_PROG_TEST_RUN](https://docs.kernel.org/bpf/bpf_prog_run.html) — Hazırlanan paketlerin gerçek çekirdek içinde çalıştırılmasını açıklar. Bu kontrol, fiziksel ağ testiyle aynı değildir.

## Bağlantı takibi, nftables ve protokoller

6. [Linux: bağlantı takibi ayarları](https://docs.kernel.org/networking/nf_conntrack-sysctl.html) — Bağlantı kapasitesi, paket/bayt sayımı ve TCP bağlantısı izleme ayarlarını açıklar.
7. [Linux: conntrack Netlink şeması](https://kernel.org/doc/html/latest/netlink/specs/conntrack.html) — Akış yönleri, bağlantı durumu ve sayaç alanları için başvuru belgesidir. WireWall gözlemi conntrack komut satırı aracıyla yapar.
8. [nftables: bağlantı durumu eşleştirme](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation) — Yeni, mevcut, ilişkili ve geçersiz bağlantı durumlarının giriş politikasında kullanılmasını açıklar.
9. [nftables: atomik kural yenileme](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement) — Bir nftables işlem dosyasının bütün olarak uygulanmasını açıklar. XDP ile nftables ortak bir atomik işlem oluşturmaz.
10. [IETF RFC 8200: IPv6](https://www.rfc-editor.org/rfc/rfc8200.html) — IPv6 başlığı, uzantı başlıkları ve parçalama kuralları için protokol başvurusudur.

## Uygulamada kullanılan bileşenler ve teknik belgeler

11. [cilium/ebpf: Go kitaplığı](https://github.com/cilium/ebpf) — WireWall, eBPF programlarını ve haritaları yüklemek, XDP programını bağlamak için bu kitaplığı kullanır.
12. [ebpf-go: kullanım belgeleri](https://ebpf-go.dev/) — eBPF nesnelerinin yüklenmesi, çekirdek özelliklerinin sorgulanması ve nesne ömrünün yönetilmesi için başvuru belgeleridir.
13. [libbpf: BPF derleme başlıkları](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html) — C programı BPF yardımcı işlev ve harita başlıklarını kullanır. Go yükleyicisi libbpf çalışma zamanına bağlı değildir.
14. [Go: resmî belgeler](https://go.dev/doc/) — Yönetim hizmeti, komut satırı aracı, HTTP API ve testler için kullanılan programlama dilinin belgeleridir.
15. [React: resmî belgeler](https://react.dev/learn) — TypeScript ile yazılan web panelinin bileşen ve durum yönetimi için başvuru belgeleridir.
16. [modernc.org/sqlite: Go sürücüsü](https://pkg.go.dev/modernc.org/sqlite@v1.61.0) — CGo gerektirmeyen SQLite sürücüsüdür. Politika, engel, denetim ve örnek olay kayıtlarında kullanılır.
17. [Prometheus: yapılandırma](https://prometheus.io/docs/prometheus/latest/configuration/configuration/) — WireWall metriklerinin ayrı bir izleme hizmetiyle düzenli olarak toplanmasını yapılandırmak için kullanılır.
18. [Grafana: dosyalarla yapılandırma](https://grafana.com/docs/grafana/latest/administration/provisioning/) — Prometheus veri kaynağının ve WireWall izleme panolarının dosyalar üzerinden hazırlanmasını açıklar.

## Tasarım araştırmasında incelenen açık kaynak projeler

19. [gamemann/xdp-firewall](https://github.com/gamemann/xdp-firewall/blob/5803917677a4a63f464bfe7143ce4f267c23d3d9/README.md) — Bağlantı durumu tutmayan kurallar, hız sınırlaması ve geçici engelleme yaklaşımı incelendi. Karşılaştırmalı çalıştırma yapılmadı.
20. [xdp-project/xdp-tools: xdp-filter](https://github.com/xdp-project/xdp-tools/blob/7873be4a618083701c81d8867766f7dc828019a5/xdp-filter/README.org) — IP, MAC ve port listeleri ile açık varsayılan karar yaklaşımı incelendi. Karşılaştırmalı çalıştırma yapılmadı.
21. [cilium/ebpf: XDP örneği](https://github.com/cilium/ebpf/blob/b5a5a86f850a29988d77b1e626fe981705032020/examples/xdp/main.go) — Program yükleme, XDP bağlantısı, harita okuma ve kaynakların kapatılması için örnek olarak incelendi.
22. [cilium/cilium](https://github.com/cilium/cilium) — Sunucu güvenlik duvarı, bağlantı takibi ve gözlemlenebilirlik için mimari araştırmada incelendi. Projeye kurulmadı.
23. [cloudflare/xdpcap](https://github.com/cloudflare/xdpcap) — XDP içinde erken düşürülen paketlerin gözlenmesi için incelendi. WireWall bu sürümde PCAP kaydı üretmez.
24. [cloudflare/bpftools](https://github.com/cloudflare/bpftools) — BPF filtresi üretimi ve paket yakalama araçları için araştırmada incelendi. Uygulamanın temeli olarak seçilmedi.
25. [xdp-project/bpf-examples: xdp-synproxy](https://github.com/xdp-project/bpf-examples/blob/main/xdp-synproxy/README.org) — Netfilter hazırlığıyla çalışan SYN proxy örneği incelendi. WireWall bu sürümde SYN proxy uygulamaz.

## Üretici belgeleri üzerinden incelenen ticari çözümler

26. [Cloudflare Network Firewall (önceki adı: Magic Firewall)](https://developers.cloudflare.com/cloudflare-network-firewall/) — Merkezî L3/L4 politika ve gözlem yaklaşımı üretici belgelerinden incelendi.
27. [Cloudflare Magic Transit](https://developers.cloudflare.com/reference-architecture/architectures/magic-transit/) — BGP ve anycast tabanlı üst ağ temizleme yaklaşımı incelendi. Sunucu içindeki güvenlik duvarından farklı bir koruma katmanıdır.
28. [AWS Network Firewall: kural motorları](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-rules-engines.html) — Bağlantı durumu tutmayan erken denetim ile bağlantı durumunu izleyen akış incelemesinin görev ayrımı incelendi.
29. [AWS Network Firewall: ücretlendirme](https://aws.amazon.com/network-firewall/pricing/) — Uç nokta çalışma süresi ve işlenen trafik üzerinden ücretlendirme modeli incelendi. Satın alma veya performans testi yapılmadı.
30. [AWS Shield Advanced: ücretlendirme ve kapsam](https://aws.amazon.com/shield/pricing/) — Yönetilen DDoS korumasının hizmet kapsamını sunucu içindeki güvenlik duvarıyla karşılaştırmak için incelendi.
31. [FortiGate / FortiGate-VM: paket işleme](https://docs.fortinet.com/document/fortigate/7.6.0/parallel-path-processing-life-of-a-packet/466137) — Paket yolu ve bağlantı oturumu denetimi için mimari araştırmada incelendi. Ürün kurulmadı.
32. [FortiGate: NP7 hızlandırma](https://docs.fortinet.com/document/fortigate/7.6.0/hardware-acceleration/765824/np7-acceleration) — Uygun donanımda oturum işlemlerinin hızlandırıcıya aktarılmasını açıklayan üretici başvurusudur. VDS üzerinde uygulanmadı.

Fortinet başvurularında erişim notu: 31 Ekim 2026 kontrolünde resmî arama sonuçları bağlantıları doğruladı; iki belgenin doğrudan içeriği HTTP 403 nedeniyle yeniden açılamadı. Bunlar önceki tasarım araştırmasının başvuruları olarak korunmuştur.

## Projenin kendi belgeleri ve ölçüm sonuçları

- [WireWall kaynak deposu](https://github.com/TheDarkGuardian/WireWall): uygulama, kurulum ve geliştirme açıklamaları.
- [Test yöntemi ve sonuçlar](../TESTING.md): gerçek çekirdek testleri, 120 izole karşılaştırma deneyi, ek 20 deneyin gecikme sonuçları ve beş dakikalık süreklilik deneyi.
- [Linux doğrulama ayrıntıları](../LINUX.md): gerçek XDP yükleme ve ağ testlerinin derleme kontrollerinden farkı.
- [Prometheus ve Grafana](../MONITORING.md): metrik toplama ve izleme kurulumu.

## Görsel kaynakları

- [Sunucu rafı görseli](../assets/server-room-illustration.png): bu sunum için yapay zekâyla üretildi. Gerçek VDS veya kurulum fotoğrafı değildir.
- [Paket filtreleme illüstrasyonu](../assets/wirewall-cover.png): proje için yapay zekâyla üretildi. Paket akışını temsili olarak anlatır.
- [Laboratuvar görseli](../assets/network-lab-illustration.png): bu sunum için yapay zekâyla üretildi. Gerçek deney ortamının fotoğrafı değildir.
- Yönetim paneli ve olay geçmişi ekranları: projenin sentetik laboratuvar görünümünden alındı; gerçek saldırı kaydı veya paket üretimi değildir.
- Grafana ekranı: gerçek Ubuntu ortamındaki native XDP ve etkin filtreleme durumundan alındı.
- Mimari ve paket yolu şemaları: WireWall uygulamasının işleyişini açıklamak için çizildi. Gecikme grafiği gerçek izole deneylerin sonuçlarını gösterir.
