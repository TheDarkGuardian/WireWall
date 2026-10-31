# Bağımlılık ve lisans envanteri

Go sürümleri go.mod/go.sum; npm sürümleri package-lock.json üzerinden kaydedilir. Kurulu paketlerin üst dizin lisans/NOTICE dosyaları third-party altında aynen korunur. Bu liste hukuki uygunluk sertifikası değildir; yayımlamadan önce dağıtılan bileşenlerin bildirimleri incelenir.

WireWall uygulaması için ayrı bir açık kaynak lisansı henüz seçilmedi. BPF kaynak başlıkları kendi SPDX bildirimlerini taşır. Grafana ve Prometheus kaynak pakete gömülmez, kendi paketleri/lisanslarıyla ayrıca kurulur.

## Go

| Modül | Sürüm | Bildirim |
|---|---|---|
| github.com/BurntSushi/toml | v1.6.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/cilium/ebpf | v0.22.0 | [dosya](third-party/go/github.com_cilium_ebpf/LICENSE.txt) |
| github.com/containerd/stargz-snapshotter/estargz | v0.16.3 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/davecgh/go-spew | v1.1.2-0.20180830191138-d8f796af33cc | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/docker/cli | v29.2.0+incompatible | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/docker/distribution | v2.8.3+incompatible | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/docker/docker-credential-helpers | v0.9.3 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/dustin/go-humanize | v1.1.0 | [dosya](third-party/go/github.com_dustin_go-humanize/LICENSE.txt) |
| github.com/go-quicktest/qt | v1.101.1-0.20240301121107-c6c8733fa1e6 | [dosya](third-party/go/github.com_go-quicktest_qt/LICENSE.txt) |
| github.com/google/go-cmp | v0.7.0 | [dosya](third-party/go/github.com_google_go-cmp/LICENSE.txt) |
| github.com/google/go-containerregistry | v0.20.6 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/google/pprof | v0.0.0-20261016150608-1facf8f91b50 | [dosya](third-party/go/github.com_google_pprof/LICENSE.txt) |
| github.com/google/uuid | v1.6.0 | [dosya](third-party/go/github.com_google_uuid/LICENSE.txt) |
| github.com/hashicorp/golang-lru/v2 | v2.0.7 | [dosya](third-party/go/github.com_hashicorp_golang-lru_v2/LICENSE.txt) |
| github.com/inconshreveable/mousetrap | v1.1.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/josharian/native | v1.1.0 | [dosya](third-party/go/github.com_josharian_native/license.txt) |
| github.com/jsimonetti/rtnetlink/v2 | v2.0.1 | [dosya](third-party/go/github.com_jsimonetti_rtnetlink_v2/LICENSE.md.txt) |
| github.com/klauspost/compress | v1.18.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/kr/pretty | v0.3.1 | [dosya](third-party/go/github.com_kr_pretty/License.txt) |
| github.com/kr/text | v0.2.0 | [dosya](third-party/go/github.com_kr_text/License.txt) |
| github.com/mattn/go-isatty | v0.0.24 | [dosya](third-party/go/github.com_mattn_go-isatty/LICENSE.txt) |
| github.com/mdlayher/netlink | v1.7.2 | [dosya](third-party/go/github.com_mdlayher_netlink/LICENSE.md.txt) |
| github.com/mdlayher/socket | v0.5.1 | [dosya](third-party/go/github.com_mdlayher_socket/LICENSE.md.txt) |
| github.com/mitchellh/go-homedir | v1.1.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/ncruces/go-strftime | v1.1.0 | [dosya](third-party/go/github.com_ncruces_go-strftime/LICENSE.txt) |
| github.com/opencontainers/go-digest | v1.0.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/opencontainers/image-spec | v1.1.1 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/pmezard/go-difflib | v1.0.1-0.20181226105442-5d4384ee4fb2 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | [dosya](third-party/go/github.com_remyoudompheng_bigfft/LICENSE.txt) |
| github.com/rogpeppe/go-internal | v1.14.1 | [dosya](third-party/go/github.com_rogpeppe_go-internal/LICENSE.txt) |
| github.com/sirupsen/logrus | v1.9.4 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/spf13/cobra | v1.10.2 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/spf13/pflag | v1.0.10 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/stretchr/testify | v1.11.1 | Kurulu modülde üst dizin bildirimi bulunamadı |
| github.com/vbatts/tar-split | v0.12.1 | Kurulu modülde üst dizin bildirimi bulunamadı |
| golang.org/x/exp/typeparams | v0.0.0-20260209203927-2842357ff358 | Kurulu modülde üst dizin bildirimi bulunamadı |
| golang.org/x/mod | v0.42.0 | [dosya](third-party/go/golang.org_x_mod/LICENSE.txt) |
| golang.org/x/net | v0.48.0 | [dosya](third-party/go/golang.org_x_net/LICENSE.txt) |
| golang.org/x/sync | v0.24.0 | [dosya](third-party/go/golang.org_x_sync/LICENSE.txt) |
| golang.org/x/sys | v0.49.0 | [dosya](third-party/go/golang.org_x_sys/LICENSE.txt) |
| golang.org/x/tools | v0.52.0 | [dosya](third-party/go/golang.org_x_tools/LICENSE.txt) |
| gotest.tools/v3 | v3.5.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| honnef.co/go/tools | v0.7.0 | Kurulu modülde üst dizin bildirimi bulunamadı |
| modernc.org/cc/v4 | v4.30.3 | [dosya](third-party/go/modernc.org_cc_v4/LICENSE.txt) |
| modernc.org/ccgo/v4 | v4.37.0 | [dosya](third-party/go/modernc.org_ccgo_v4/LICENSE.txt) |
| modernc.org/fileutil | v1.4.0 | [dosya](third-party/go/modernc.org_fileutil/LICENSE.txt) |
| modernc.org/gc/v2 | v2.6.5 | [dosya](third-party/go/modernc.org_gc_v2/LICENSE.txt) |
| modernc.org/gc/v3 | v3.2.0 | [dosya](third-party/go/modernc.org_gc_v3/LICENSE.txt) |
| modernc.org/goabi0 | v0.2.0 | [dosya](third-party/go/modernc.org_goabi0/LICENSE.txt) |
| modernc.org/libc | v1.79.0 | [dosya](third-party/go/modernc.org_libc/LICENSE.txt), [dosya](third-party/go/modernc.org_libc/LICENSE-3RD-PARTY.md.txt) |
| modernc.org/mathutil | v1.7.1 | [dosya](third-party/go/modernc.org_mathutil/LICENSE.txt) |
| modernc.org/memory | v1.12.1 | [dosya](third-party/go/modernc.org_memory/LICENSE.txt), [dosya](third-party/go/modernc.org_memory/LICENSE-GO.txt), [dosya](third-party/go/modernc.org_memory/LICENSE-LOGO.txt), [dosya](third-party/go/modernc.org_memory/LICENSE-MMAP-GO.txt) |
| modernc.org/opt | v0.2.0 | [dosya](third-party/go/modernc.org_opt/LICENSE.txt) |
| modernc.org/sortutil | v1.2.1 | [dosya](third-party/go/modernc.org_sortutil/LICENSE.txt) |
| modernc.org/sqlite | v1.61.0 | [dosya](third-party/go/modernc.org_sqlite/LICENSE.txt), [dosya](third-party/go/modernc.org_sqlite/LICENSE-3RD-PARTY.md.txt), [dosya](third-party/go/modernc.org_sqlite/LICENSE-SQLITE.txt), [dosya](third-party/go/modernc.org_sqlite/LICENSE-SQLITE_VEC.txt) |
| modernc.org/strutil | v1.2.1 | [dosya](third-party/go/modernc.org_strutil/LICENSE.txt) |
| modernc.org/token | v1.1.0 | [dosya](third-party/go/modernc.org_token/LICENSE.txt) |

## npm (build/test bağımlılıkları dahil)

| Paket | Sürüm | Paket lisans bilgisi | Kapsam |
|---|---|---|---|
| @babel/code-frame | 7.29.7 | MIT | geliştirme |
| @babel/compat-data | 7.29.7 | MIT | geliştirme |
| @babel/core | 7.29.7 | MIT | geliştirme |
| @babel/generator | 7.29.8 | MIT | geliştirme |
| @babel/helper-compilation-targets | 7.29.7 | MIT | geliştirme |
| @babel/helper-globals | 7.29.7 | MIT | geliştirme |
| @babel/helper-module-imports | 7.29.7 | MIT | geliştirme |
| @babel/helper-module-transforms | 7.29.7 | MIT | geliştirme |
| @babel/helper-plugin-utils | 7.29.7 | MIT | geliştirme |
| @babel/helper-string-parser | 7.29.11 | MIT | geliştirme |
| @babel/helper-validator-identifier | 7.29.7 | MIT | geliştirme |
| @babel/helper-validator-option | 7.29.7 | MIT | geliştirme |
| @babel/helpers | 7.29.10 | MIT | geliştirme |
| @babel/parser | 7.29.11 | MIT | geliştirme |
| @babel/plugin-transform-react-jsx-self | 7.29.7 | MIT | geliştirme |
| @babel/plugin-transform-react-jsx-source | 7.29.7 | MIT | geliştirme |
| @babel/template | 7.29.7 | MIT | geliştirme |
| @babel/traverse | 7.29.10 | MIT | geliştirme |
| @babel/types | 7.29.11 | MIT | geliştirme |
| @esbuild/aix-ppc64 | 0.28.2 | MIT | geliştirme |
| @esbuild/android-arm | 0.28.2 | MIT | geliştirme |
| @esbuild/android-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/android-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/darwin-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/darwin-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/freebsd-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/freebsd-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-arm | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-ia32 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-loong64 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-mips64el | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-ppc64 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-riscv64 | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-s390x | 0.28.2 | MIT | geliştirme |
| @esbuild/linux-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/netbsd-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/netbsd-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/openbsd-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/openbsd-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/openharmony-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/sunos-x64 | 0.28.2 | MIT | geliştirme |
| @esbuild/win32-arm64 | 0.28.2 | MIT | geliştirme |
| @esbuild/win32-ia32 | 0.28.2 | MIT | geliştirme |
| @esbuild/win32-x64 | 0.28.2 | MIT | geliştirme |
| @fontsource/ibm-plex-mono | 5.3.0 | OFL-1.1 | çalışma |
| @fontsource/inter | 5.3.0 | OFL-1.1 | çalışma |
| @jridgewell/gen-mapping | 0.3.13 | MIT | geliştirme |
| @jridgewell/remapping | 2.3.5 | MIT | geliştirme |
| @jridgewell/resolve-uri | 3.1.2 | MIT | geliştirme |
| @jridgewell/sourcemap-codec | 1.6.0 | MIT | geliştirme |
| @jridgewell/trace-mapping | 0.3.31 | MIT | geliştirme |
| @napi-rs/lzma-linux-x64-gnu | 1.5.1 | MIT | geliştirme |
| @playwright/test | 1.64.1 | Apache-2.0 | geliştirme |
| @rolldown/pluginutils | 1.0.0-rc.3 | MIT | geliştirme |
| @rollup/rollup-android-arm-eabi | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-android-arm64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-darwin-arm64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-darwin-x64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-freebsd-arm64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-freebsd-x64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-arm-gnueabihf | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-arm-musleabihf | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-arm64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-arm64-musl | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-loong64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-loong64-musl | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-ppc64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-ppc64-musl | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-riscv64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-riscv64-musl | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-s390x-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-x64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-linux-x64-musl | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-openbsd-x64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-openharmony-arm64 | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-win32-arm64-msvc | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-win32-ia32-msvc | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-win32-x64-gnu | 4.65.1 | MIT | geliştirme |
| @rollup/rollup-win32-x64-msvc | 4.65.1 | MIT | geliştirme |
| @types/babel__core | 7.20.5 | MIT | geliştirme |
| @types/babel__generator | 7.27.0 | MIT | geliştirme |
| @types/babel__template | 7.4.4 | MIT | geliştirme |
| @types/babel__traverse | 7.28.0 | MIT | geliştirme |
| @types/estree | 1.0.9 | MIT | geliştirme |
| @types/react | 19.3.0 | MIT | geliştirme |
| @types/react-dom | 19.3.0 | MIT | geliştirme |
| @vitejs/plugin-react | 5.2.0 | MIT | geliştirme |
| baseline-browser-mapping | 2.11.33 | Apache-2.0 | geliştirme |
| browserslist | 4.29.5 | MIT | geliştirme |
| caniuse-lite | 1.0.30001819 | CC-BY-4.0 | geliştirme |
| convert-source-map | 2.0.0 | MIT | geliştirme |
| csstype | 3.2.3 | MIT | geliştirme |
| debug | 4.4.3 | MIT | geliştirme |
| electron-to-chromium | 1.5.465 | ISC | geliştirme |
| esbuild | 0.28.2 | MIT | geliştirme |
| escalade | 3.2.0 | MIT | geliştirme |
| fdir | 6.5.0 | MIT | geliştirme |
| fsevents | 2.3.3 | MIT | geliştirme |
| gensync | 1.0.0-beta.2 | MIT | geliştirme |
| js-tokens | 4.0.0 | MIT | geliştirme |
| jsesc | 3.1.0 | MIT | geliştirme |
| json5 | 2.2.3 | MIT | geliştirme |
| lru-cache | 5.1.1 | ISC | geliştirme |
| lucide-react | 0.468.0 | ISC | çalışma |
| ms | 2.1.3 | MIT | geliştirme |
| nanoid | 3.3.20 | MIT | geliştirme |
| node-releases | 2.0.60 | MIT | geliştirme |
| picocolors | 1.1.1 | ISC | geliştirme |
| picomatch | 4.0.7 | MIT | geliştirme |
| playwright | 1.64.1 | Apache-2.0 | geliştirme |
| playwright-core | 1.64.1 | Apache-2.0 | geliştirme |
| postcss | 8.5.32 | MIT | geliştirme |
| react | 19.3.1 | MIT | çalışma |
| react-dom | 19.3.1 | MIT | çalışma |
| react-refresh | 0.18.0 | MIT | geliştirme |
| rollup | 4.65.1 | MIT | geliştirme |
| scheduler | 0.28.0 | MIT | çalışma |
| semver | 6.3.1 | ISC | geliştirme |
| source-map-js | 1.2.2 | BSD-3-Clause | geliştirme |
| tinyglobby | 0.2.17 | MIT | geliştirme |
| typescript | 5.9.3 | Apache-2.0 | geliştirme |
| update-browserslist-db | 1.3.4 | MIT | geliştirme |
| vite | 7.3.7 | MIT | geliştirme |
| yallist | 3.1.1 | ISC | geliştirme |

Makine tarafından okunabilir sürüm ve bildirim yolları: [inventory.json](third-party/inventory.json).

Windows üzerinde farklı platformlara ait opsiyonel npm paketleri kurulu olmayabilir; bu girdiler sürüm/lisans metadatasıyla listelenir, olmayan dosya varmış gibi kopyalanmaz.

Derleme araçları: resmi Go SDK (BSD bildirimi kopyalandı); Clang/LLVM, Linux UAPI ve libbpf başlıkları kendi lisanslarıyla ayrı sağlanır. Taşınabilir SDK/cache dosyaları kaynak arşivine alınmaz.
