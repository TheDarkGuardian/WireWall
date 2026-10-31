package control

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/dataplane"
	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
	"github.com/TheDarkGuardian/WireWall/internal/model"
)

type XDPRuntime struct {
	mu             sync.Mutex
	manager        *dataplane.Manager
	policy         model.Policy
	bans           []model.Ban
	initialNFT     hostfirewall.Snapshot
	dataDir        string
	guard          *activationGuard
	ownership      *NetworkOwnership
	events         []Event
	eventLost      uint64
	last           Metrics
	lastAt         time.Time
	connections    []Connection
	conntrackAt    time.Time
	conntrackError string
	nftCounters    hostfirewall.Counters
	nftAt          time.Time
	failed         bool
	identity       string
	resumed        bool
}

func NewXDPRuntime(ctx context.Context, p model.Policy, bans []model.Ban, object, dataDir string, ownership *NetworkOwnership, resume ...bool) (*XDPRuntime, error) {
	if runtime.GOOS != "linux" {
		return nil, dataplane.ErrUnsupported
	}
	if err := ownership.check(dataDir); err != nil {
		return nil, err
	}
	if len(p.ManagementCIDRs) == 0 {
		return nil, errors.New("gerçek mod yönetim CIDR adresi gerektirir")
	}
	for _, cidr := range p.ManagementCIDRs {
		if strings.HasPrefix(cidr, "127.") || cidr == "::1/128" {
			return nil, errors.New("gerçek modda yalnız loopback yönetim adresi kullanılamaz; gerçek yönetim ağını tanımlayın")
		}
	}
	preflight, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	snapshot, err := hostfirewall.Capture(preflight)
	if err != nil {
		return nil, err
	}
	if err = hostfirewall.Apply(preflight, p, true); err != nil {
		return nil, err
	}
	r := &XDPRuntime{policy: clonePolicy(p), bans: append([]model.Ban{}, bans...), initialNFT: snapshot, dataDir: dataDir, ownership: ownership, events: []Event{}, connections: []Connection{}}
	manager, err := dataplane.New(dataplane.Options{ObjectPath: object, Interface: p.Interface, Mode: p.XDPMode, OnEvent: func(event dataplane.Event) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.events) >= 300 {
			r.eventLost++
			return
		}
		r.events = append(r.events, Event{ID: newID(), PolicyVersion: event.PolicyVersion, Timestamp: event.Time, Source: event.Packet.Source, Destination: event.Packet.Destination, SourcePort: event.Packet.SourcePort, DestinationPort: event.Packet.DestinationPort, Protocol: event.Packet.Protocol, Length: event.Packet.Length, Action: event.Action, Reason: event.Reason, RuleID: event.RuleID, WouldDrop: event.WouldDrop, Simulated: false})
	}})
	if err != nil {
		return nil, err
	}
	r.manager = manager
	r.identity, err = deploymentIdentity(p, object)
	if err != nil {
		manager.Close()
		return nil, err
	}
	if len(resume) > 0 && resume[0] {
		record, readErr := readResume(dataDir)
		r.resumed = readErr == nil && matchesResume(record, p, bans, r.identity, time.Now())
	}
	var guard *activationGuard
	if !r.resumed {
		guard, err = armGuard(dataDir, guardState{Interface: p.Interface, XDPMode: p.XDPMode, Deadline: time.Now().Add(90 * time.Second), NFT: snapshot, PreviousPolicy: p, PreviousBans: bans, DataDir: dataDir}, ownership)
	}
	if err != nil {
		manager.Close()
		return nil, err
	}
	r.guard = guard
	if err = hostfirewall.Apply(preflight, p, false); err == nil {
		err = manager.Start(ctx, p)
	}
	if err == nil {
		err = manager.Apply(p, bans)
	}
	if err == nil {
		var current dataplane.Snapshot
		current, err = manager.Snapshot()
		if err == nil {
			if guard != nil {
				err = guard.SetAttachment(current.ProgramID, current.LinkID)
			}
		}
	}
	if err != nil {
		closeErr := manager.Close()
		restoreErr := hostfirewall.Restore(preflight, snapshot)
		if restoreErr == nil && closeErr == nil && guard != nil {
			restoreErr = guard.Confirm()
		}
		return nil, errors.Join(err, closeErr, restoreErr)
	}
	return r, nil
}
func (r *XDPRuntime) Apply(p model.Policy, bans []model.Ban) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed || r.guard != nil && r.guard.Err() != nil {
		r.failed = true
		return errors.New("bağımsız watchdog geri aldı; yeniden başlatmadan yeni politika uygulanamaz")
	}
	if r.guard != nil && r.guard.Pending() {
		// Persistence failure recovery may restore the pre-activation policy. A new
		// user mutation while activation is pending is never accepted.
		if reflect.DeepEqual(p, r.guard.state.PreviousPolicy) && reflect.DeepEqual(bans, r.guard.state.PreviousBans) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := errors.Join(r.manager.Restore(p, bans), hostfirewall.Restore(ctx, r.guard.state.NFT))
			if err == nil {
				err = r.guard.Confirm()
				r.policy = clonePolicy(p)
				r.bans = append([]model.Ban{}, bans...)
			}
			if err != nil {
				r.failed = true
			}
			return err
		}
		return errors.New("önce bekleyen aktivasyonu yeni SSH oturumundan doğrulayın veya geri alın")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	snapshot, err := hostfirewall.Capture(ctx)
	if err != nil {
		return err
	}
	if err = hostfirewall.Apply(ctx, p, true); err != nil {
		return err
	}
	current, err := r.manager.Snapshot()
	if err != nil {
		return err
	}
	guard, err := armGuard(r.dataDir, guardState{Interface: p.Interface, XDPMode: p.XDPMode, ProgramID: current.ProgramID, LinkID: current.LinkID, Deadline: time.Now().Add(90 * time.Second), NFT: snapshot, PreviousPolicy: r.policy, PreviousBans: r.bans, DataDir: r.dataDir}, r.ownership)
	if err != nil {
		return err
	}
	if err = hostfirewall.Apply(ctx, p, false); err == nil {
		err = r.manager.Apply(p, bans)
	}
	if err != nil {
		// Keep ownership of this recovery even when immediate rollback fails.
		// An older confirmed guard must never permit another mutation while the
		// newly armed watchdog can still restore or detach the current dataplane.
		r.guard = guard
		restoreErr := errors.Join(r.manager.Restore(r.policy, r.bans), hostfirewall.Restore(ctx, snapshot))
		if restoreErr == nil {
			restoreErr = guard.Confirm()
		}
		if restoreErr != nil {
			r.failed = true
		}
		return errors.Join(err, restoreErr)
	}
	r.guard = guard
	r.policy = clonePolicy(p)
	r.bans = append([]model.Ban{}, bans...)
	return nil
}
func (r *XDPRuntime) Confirm() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guard == nil {
		return nil
	}
	if err := r.guard.Err(); err != nil {
		r.failed = true
		return fmt.Errorf("aktivasyon başarısız; servis yeniden başlatılmalı: %w", err)
	}
	if err := r.guard.Confirm(); err != nil {
		return err
	}
	r.resumed = false
	return r.rememberConfirmed()
}
func (r *XDPRuntime) ActivationStatus() (bool, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guard == nil {
		return false, time.Time{}
	}
	return r.guard.Pending(), r.guard.Deadline()
}
func (r *XDPRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.manager.Close()
	if r.guard != nil && r.guard.Pending() {
		restoreErr := hostfirewall.Restore(ctx, r.guard.state.NFT)
		if restoreErr == nil {
			store, openErr := OpenStore(r.dataDir)
			if openErr != nil {
				restoreErr = openErr
			} else {
				restoreErr = store.Save(r.guard.state.PreviousPolicy, r.guard.state.PreviousBans, "activation.cancel", "Servis geçici aktivasyon sırasında durduruldu")
				_ = store.Close()
			}
		}
		if restoreErr == nil {
			restoreErr = r.guard.Confirm()
		}
		return errors.Join(err, restoreErr)
	}
	return err
}
func (r *XDPRuntime) Snapshot() (LiveSnapshot, error) {
	r.mu.Lock()
	failed := r.failed
	r.mu.Unlock()
	if failed {
		return LiveSnapshot{}, errors.New("veri yolu kurtarma hatasından sonra yeniden başlatılmalı")
	}
	// Do not hold the event mutex while asking the loader for maps: loader event
	// delivery can run concurrently and must not deadlock on callback acquisition.
	snapshot, err := r.manager.Snapshot()
	if err != nil {
		return LiveSnapshot{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.guard != nil && r.guard.Err() != nil {
		r.failed = true
		return LiveSnapshot{}, errors.New("aktivasyon zaman aşımında güvenli geri alma yapıldı; servis yeniden başlatılmalı")
	}
	pass := snapshot.Counters["pass"]
	drop := snapshot.Counters["drop"]
	m := Metrics{ReceivedPackets: pass.Packets + drop.Packets, PassedPackets: pass.Packets, DroppedPackets: drop.Packets, WouldDropPackets: snapshot.Counters["would_drop"].Packets, ReceivedBytes: pass.Bytes + drop.Bytes, MapCapacityFailures: snapshot.Counters["capacity_fallback"].Packets, EventDrops: r.eventLost + snapshot.Counters["event_lost"].Packets, BlockedSources: snapshot.BanEntries, Reasons: []ReasonCount{}, Protocols: []ProtocolCount{}, Services: []ServiceCount{}}
	for _, name := range []string{"malformed", "banned", "rule_drop", "service_limit", "source_limit", "complex_packet", "byte_limit", "source_byte_limit"} {
		if n := snapshot.Counters[name].Packets; n > 0 {
			m.Reasons = append(m.Reasons, ReasonCount{name, n})
		}
	}
	now := time.Now()
	for name, counter := range snapshot.Protocols {
		if counter.Packets > 0 {
			m.Protocols = append(m.Protocols, ProtocolCount{name, counter.Packets})
		}
	}
	sort.Slice(m.Protocols, func(i, j int) bool { return m.Protocols[i].Protocol < m.Protocols[j].Protocol })
	for key, counter := range snapshot.Services {
		proto := "tcp"
		if key>>16 == 17 {
			proto = "udp"
		}
		m.Services = append(m.Services, ServiceCount{uint16(key), proto, counter.Packets})
	}
	sort.Slice(m.Services, func(i, j int) bool {
		if m.Services[i].Packets == m.Services[j].Packets {
			if m.Services[i].Protocol == m.Services[j].Protocol {
				return m.Services[i].Port < m.Services[j].Port
			}
			return m.Services[i].Protocol < m.Services[j].Protocol
		}
		return m.Services[i].Packets > m.Services[j].Packets
	})
	if len(m.Services) > 20 {
		m.Services = m.Services[:20]
	}
	m.ServiceStatsOverflow = snapshot.Counters["service_stats_overflow"].Packets
	if now.Sub(r.nftAt) > 5*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		r.nftCounters, err = hostfirewall.ReadCounters(ctx)
		cancel()
		r.nftAt = now
		if err != nil {
			r.nftCounters = hostfirewall.Counters{Error: err.Error()}
		}
	}
	m.HostFirewall = r.nftCounters
	if !r.lastAt.IsZero() {
		seconds := now.Sub(r.lastAt).Seconds()
		m.PPS = float64(m.ReceivedPackets-r.last.ReceivedPackets) / seconds
		m.BPS = float64(m.ReceivedBytes-r.last.ReceivedBytes) * 8 / seconds
		m.DropPPS = float64(m.DroppedPackets-r.last.DroppedPackets) / seconds
	}
	r.last = m
	r.lastAt = now
	if now.Sub(r.conntrackAt) > 5*time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		flows, e := readConntrack(ctx)
		cancel()
		r.conntrackAt = now
		if e != nil {
			r.conntrackError = e.Error()
			r.connections = []Connection{}
		} else {
			r.connections = flows
			r.conntrackError = ""
		}
	}
	health := []Health{{"XDP", "ok", "Sayaçlar ve protokol/ilk 20 hedef port dağılımı örneklenmeyen kernel map'lerinden okunuyor"}, {"Metrik kapsamı", "info", "XDP giriş sayaçları; nftables değerleri XDP sonrasındaki host input kararlarıdır. Servis tablosu 1024 port/protokol ile sınırlı; taşma ayrıca sayılır. Yeniden başlatmada XDP, politika uygulamada nft sayaçları sıfırlanır."}}
	if !r.nftCounters.Available {
		// A read failure must never present old host verdicts as fresh counters.
		health = append(health, Health{"nftables sayaçları", "warning", r.nftCounters.Error})
	}
	if r.resumed {
		health = append(health, Health{"Onaylı başlangıç", "ok", "Aynı politika, etkin engeller, arayüz adresleri/MAC ve program SHA256 değerleri önceki operatör onayıyla eşleşti. Yeni ağ değişiklikleri yine süreli onay gerektirir."})
	}
	health = append(health, Health{"Map kayıtları", "info", fmt.Sprintf("Etkin nesil: %d kaynak limit kaydı, %d süreli engel; kapasite hataları ayrıca sayılır", snapshot.SourceEntries, snapshot.BanEntries)})
	if r.conntrackError != "" {
		health = append(health, Health{"Conntrack", "warning", r.conntrackError})
	}
	if snapshot.CleanupError != "" {
		health = append(health, Health{"Nesil temizliği", "warning", snapshot.CleanupError})
	}
	if snapshot.RetiredGenerations > 0 {
		health = append(health, Health{"Korunan eski nesiller", "info", fmt.Sprintf("%d nesil, eski okuyucular tamamlanana kadar tutuluyor", snapshot.RetiredGenerations)})
	}
	if r.guard != nil && r.guard.Pending() {
		health = append(health, Health{"Aktivasyon", "warning", "90 saniyelik geri alma etkin; yeni SSH oturumunu doğruladıktan sonra aktivasyonu onaylayın"})
	}
	events := append([]Event{}, r.events...)
	r.events = r.events[:0]
	return LiveSnapshot{Metrics: m, Events: events, Connections: append([]Connection{}, r.connections...), Health: health, Attached: snapshot.Attached, XDPMode: snapshot.Mode}, nil
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("conntrack çıktısı kapasite sınırını aştı")
	}
	return b.Buffer.Write(p)
}
func readConntrack(ctx context.Context) ([]Connection, error) {
	if runtime.GOOS != "linux" {
		return nil, dataplane.ErrUnsupported
	}
	cmd := exec.CommandContext(ctx, "conntrack", "-L", "-o", "extended")
	out := &limitedBuffer{max: 512 << 10}
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("conntrack okunamadı: %w; %s", err, strings.TrimSpace(stderr.String()))
	}
	return parseConntrack(out.String(), time.Now().UTC()), nil
}
func parseConntrack(text string, now time.Time) []Connection {
	result := []Connection{}
	for _, line := range strings.Split(text, "\n") {
		if len(result) >= 256 {
			break
		}
		fields := strings.Fields(line)
		var c Connection
		c.ObservedAt = now
		c.Direction = "original"
		seen := map[string]bool{}
		for _, field := range fields {
			switch field {
			case "tcp", "udp", "icmp", "icmpv6":
				c.Protocol = field
			case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK":
				c.State = field
			}
			pair := strings.SplitN(field, "=", 2)
			if len(pair) != 2 || seen[pair[0]] {
				continue
			}
			seen[pair[0]] = true
			switch pair[0] {
			case "src":
				c.Source = pair[1]
			case "dst":
				c.Destination = pair[1]
			case "sport":
				v, _ := strconv.ParseUint(pair[1], 10, 16)
				c.SourcePort = uint16(v)
			case "dport":
				v, _ := strconv.ParseUint(pair[1], 10, 16)
				c.DestinationPort = uint16(v)
			case "packets":
				c.Packets, _ = strconv.ParseUint(pair[1], 10, 64)
			case "bytes":
				c.Bytes, _ = strconv.ParseUint(pair[1], 10, 64)
			}
		}
		if c.Source == "" || c.Destination == "" || c.Protocol == "" {
			continue
		}
		c.AccountingAvailable = seen["packets"] && seen["bytes"]
		if c.State == "" {
			c.State = "TRACKED"
		}
		c.ID = fmt.Sprintf("%s/%s/%d/%s/%d", c.Protocol, c.Source, c.SourcePort, c.Destination, c.DestinationPort)
		result = append(result, c)
	}
	return result
}
