package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/detection"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

var ErrConflict = errors.New("politika sürümü değişti; güncel politikayı tekrar yükleyin")

type Runtime interface {
	Apply(model.Policy, []model.Ban) error
	Snapshot() (LiveSnapshot, error)
	Close() error
}
type LiveSnapshot struct {
	Metrics     Metrics
	Events      []Event
	Connections []Connection
	Health      []Health
	Attached    bool
	XDPMode     string
}
type Service struct {
	mu                sync.RWMutex
	store             *Store
	policy            model.Policy
	bans              []model.Ban
	evaluator         *policy.Evaluator
	started           time.Time
	observedAt        time.Time
	backend, scenario string
	metrics           Metrics
	history           []Point
	events            []Event
	connections       []Connection
	reasons           map[string]uint64
	protocols         map[string]uint64
	services          map[string]ServiceCount
	blocked           map[string]bool
	runtime           Runtime
	hostname          string
	storageError      string
	labClock          time.Time
	liveStatus        LiveSnapshot
	resources         *ResourceSampler
	detector          *detection.Detector
}

func newID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("system random unavailable")
	}
	return hex.EncodeToString(raw[:])
}
func NewService(store *Store, initial *model.Policy, backend string) (*Service, error) {
	p, bans, found, err := store.Load()
	if err != nil {
		return nil, err
	}
	persistInitial := !found || initial != nil
	if initial != nil {
		p = *initial
		found = true
	}
	if !found {
		p = policy.Default()
	}
	if err = policy.Validate(p); err != nil {
		return nil, err
	}
	validBans := []model.Ban{}
	for _, ban := range bans {
		if !ban.ExpiresAt.After(time.Now()) {
			continue
		}
		if err = policy.ValidateBan(ban); err != nil {
			return nil, fmt.Errorf("persisted ban: %w", err)
		}
		validBans = append(validBans, ban)
	}
	if len(validBans) > 4096 {
		return nil, errors.New("persisted ban capacity exceeded")
	}
	bans = validBans
	if backend != "lab" && backend != "xdp" {
		return nil, fmt.Errorf("unknown backend %q", backend)
	}
	host, _ := os.Hostname()
	s := &Service{store: store, policy: clonePolicy(p), bans: append([]model.Ban{}, bans...), started: time.Now().UTC(), backend: backend, scenario: "normal", hostname: host, resources: NewResourceSampler()}
	s.resetLocked()
	s.events, err = store.LoadEvents(300, backend == "lab")
	if err != nil {
		return nil, err
	}
	if persistInitial {
		detail := "Başlangıç XDP politikası"
		if backend == "lab" {
			detail = "Başlangıç laboratuvar politikası"
		}
		if err = store.Save(p, bans, "initialize", detail); err != nil {
			return nil, err
		}
	}
	return s, nil
}
func (s *Service) SetRuntime(r Runtime) { s.mu.Lock(); defer s.mu.Unlock(); s.runtime = r }
func (s *Service) ConfirmActivation() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	confirmer, ok := s.runtime.(interface{ Confirm() error })
	if !ok {
		return errors.New("bekleyen gerçek aktivasyon yok")
	}
	if err := confirmer.Confirm(); err != nil {
		return err
	}
	if err := s.store.Save(s.policy, s.bans, "activation.confirm", "Operatör yönetim erişimini doğruladı"); err != nil {
		s.storageError = "Aktivasyon onaylandı; audit kaydı yazılamadı: " + err.Error()
		return errors.New(s.storageError)
	}
	return nil
}
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if s.backend == "lab" {
				s.labTick(now.UTC())
			} else {
				s.liveTick(now.UTC())
			}
		}
	}
}
func (s *Service) Close() error {
	if s.runtime != nil {
		return s.runtime.Close()
	}
	return nil
}
func clonePolicy(p model.Policy) model.Policy {
	p.Rules = append([]model.Rule{}, p.Rules...)
	p.ManagementCIDRs = append([]string{}, p.ManagementCIDRs...)
	p.Host.TCPPorts = append([]uint16{}, p.Host.TCPPorts...)
	p.Host.UDPPorts = append([]uint16{}, p.Host.UDPPorts...)
	return p
}
func (s *Service) Policy() model.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePolicy(s.policy)
}
func (s *Service) Bans() []model.Ban {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Ban{}, s.bans...)
}
func (s *Service) ApplyPolicy(p model.Policy, expected uint64) (model.Policy, error) {
	if err := policy.Validate(p); err != nil {
		return model.Policy{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != s.policy.Version {
		return model.Policy{}, ErrConflict
	}
	if p.Interface != s.policy.Interface && s.runtime != nil {
		return model.Policy{}, errors.New("arayüz değişikliği servis yeniden başlatması gerektirir")
	}
	if p.XDPMode != s.policy.XDPMode && s.runtime != nil {
		return model.Policy{}, errors.New("XDP modu değişikliği servis yeniden başlatması gerektirir")
	}
	p.Version = s.policy.Version + 1
	old := s.policy
	if s.runtime != nil {
		if err := s.runtime.Apply(p, s.bans); err != nil {
			return model.Policy{}, err
		}
	}
	if err := s.store.Save(p, s.bans, "policy.apply", fmt.Sprintf("Politika %d → %d", old.Version, p.Version)); err != nil {
		return model.Policy{}, s.recoverPersistence(err, old, s.bans)
	}
	s.policy = clonePolicy(p)
	s.evaluator = s.newEvaluator()
	return clonePolicy(p), nil
}
func (s *Service) AddBan(address, reason string, seconds int) (model.Ban, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return model.Ban{}, errors.New("geçerli tekil IP adresi gerekli")
	}
	ip = ip.Unmap()
	reason = strings.TrimSpace(reason)
	if len(reason) < 3 || len(reason) > 240 {
		return model.Ban{}, errors.New("gerekçe 3–240 karakter olmalı")
	}
	if seconds < 1 || seconds > 86400 {
		return model.Ban{}, errors.New("süre 1–86400 saniye olmalı")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireBansLocked(time.Now())
	if len(s.bans) >= 4096 {
		return model.Ban{}, errors.New("engel tablosu dolu")
	}
	for _, cidr := range s.policy.ManagementCIDRs {
		prefix, e := netip.ParsePrefix(cidr)
		if e == nil && prefix.Contains(ip) {
			return model.Ban{}, errors.New("yönetim ağı engellenemez")
		}
	}
	for _, b := range s.bans {
		if b.Address == ip.String() {
			return model.Ban{}, errors.New("bu IP zaten engelli")
		}
	}
	now := time.Now().UTC()
	b := model.Ban{ID: newID(), Address: ip.String(), Reason: reason, CreatedAt: now, ExpiresAt: now.Add(time.Duration(seconds) * time.Second)}
	next := append(append([]model.Ban{}, s.bans...), b)
	if s.runtime != nil {
		if err = s.runtime.Apply(s.policy, next); err != nil {
			return model.Ban{}, err
		}
	}
	if err = s.store.Save(s.policy, next, "ban.add", b.Address+": "+reason); err != nil {
		return model.Ban{}, s.recoverPersistence(err, s.policy, s.bans)
	}
	s.bans = next
	return b, nil
}
func (s *Service) DeleteBan(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := []model.Ban{}
	found := false
	for _, b := range s.bans {
		if b.ID == id {
			found = true
		} else {
			next = append(next, b)
		}
	}
	if !found {
		return os.ErrNotExist
	}
	if s.runtime != nil {
		if err := s.runtime.Apply(s.policy, next); err != nil {
			return err
		}
	}
	if err := s.store.Save(s.policy, next, "ban.delete", id); err != nil {
		return s.recoverPersistence(err, s.policy, s.bans)
	}
	s.bans = next
	return nil
}
func (s *Service) SetScenario(name string) error {
	if s.backend != "lab" {
		return errors.New("yalnız laboratuvar modunda kullanılabilir")
	}
	switch name {
	case "normal", "syn-burst", "udp-burst", "port-scan", "mixed":
	default:
		return errors.New("bilinmeyen senaryo")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scenario = name
	return nil
}
func (s *Service) Reset() error {
	if s.backend != "lab" {
		return errors.New("yalnız laboratuvar modunda kullanılabilir")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store.ClearLabEvents(); err != nil {
		return err
	}
	s.resetLocked()
	return nil
}
func (s *Service) newEvaluator() *policy.Evaluator {
	if s.backend == "lab" {
		return policy.NewEvaluatorWithClock(func() time.Time { return s.labClock })
	}
	return policy.NewEvaluator()
}
func (s *Service) resetLocked() {
	s.metrics = Metrics{Reasons: []ReasonCount{}, Protocols: []ProtocolCount{}, Services: []ServiceCount{}}
	s.history = []Point{}
	s.events = []Event{}
	s.connections = []Connection{}
	s.reasons = map[string]uint64{}
	s.protocols = map[string]uint64{}
	s.services = map[string]ServiceCount{}
	s.blocked = map[string]bool{}
	s.labClock = time.Now().UTC()
	s.evaluator = s.newEvaluator()
	opts := detection.Options{}
	if s.backend == "lab" {
		opts.Clock = func() time.Time { return s.labClock }
	}
	s.detector = detection.New(opts)
}
func (s *Service) expireBansLocked(now time.Time) {
	next := s.bans[:0]
	for _, b := range s.bans {
		if b.ExpiresAt.After(now) {
			next = append(next, b)
		}
	}
	s.bans = next
}
func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := clonePolicy(s.policy)
	sys := System{Name: "WireWall", Version: "0.1.0", Backend: s.backend, Platform: runtime.GOOS + "/" + runtime.GOARCH, Hostname: s.hostname, Interface: p.Interface, XDPMode: p.XDPMode, Mode: p.Mode, PolicyVersion: p.Version, StartedAt: s.started, UptimeSeconds: int64(time.Since(s.started).Seconds()), Simulated: s.backend == "lab", Scenario: s.scenario, Capabilities: []Capability{}, Health: []Health{}}
	if s.resources != nil {
		sys.Resources = s.resources.Sample()
	}
	sys.ObservedAt = s.observedAt
	if s.backend == "lab" {
		sys.XDPMode = "unattached"
		sys.Capabilities = []Capability{{"XDP kernel", false, "Laboratuvar modu; gerçek arayüze program bağlı değil"}, {"Politika değerlendirme", true, "Sentetik paket açıklamaları"}, {"Conntrack", false, "Bağlantı satırları laboratuvar örnekleridir"}}
		sys.Health = []Health{{"Laboratuvar", "ok", "Gerçek trafik gönderilmez ve host korunmaz"}}
	} else {
		sys.Attached = s.liveStatus.Attached
		sys.XDPMode = s.liveStatus.XDPMode
		sys.Capabilities = []Capability{{"XDP kernel", sys.Attached, "Linux veri yolu"}}
		sys.Health = append([]Health{}, s.liveStatus.Health...)
	}
	if s.storageError != "" {
		sys.Health = append(sys.Health, Health{"Kayıt", "error", s.storageError})
	}
	if activation, ok := s.runtime.(interface{ ActivationStatus() (bool, time.Time) }); ok {
		sys.ActivationPending, sys.ActivationDeadline = activation.ActivationStatus()
	}
	m := s.metrics
	m.Reasons = append([]ReasonCount{}, m.Reasons...)
	m.Protocols = append([]ProtocolCount{}, m.Protocols...)
	m.Services = append([]ServiceCount{}, m.Services...)
	if s.backend == "lab" {
		m.Reasons = []ReasonCount{}
		for reason, count := range s.reasons {
			m.Reasons = append(m.Reasons, ReasonCount{reason, count})
		}
		sort.Slice(m.Reasons, func(i, j int) bool { return m.Reasons[i].Count > m.Reasons[j].Count })
		m.Protocols = []ProtocolCount{}
		for proto, n := range s.protocols {
			m.Protocols = append(m.Protocols, ProtocolCount{proto, n})
		}
		sort.Slice(m.Protocols, func(i, j int) bool { return m.Protocols[i].Protocol < m.Protocols[j].Protocol })
		m.Services = []ServiceCount{}
		for _, v := range s.services {
			m.Services = append(m.Services, v)
		}
		sort.Slice(m.Services, func(i, j int) bool { return m.Services[i].Packets > m.Services[j].Packets })
		m.BlockedSources = len(s.blocked)
	}
	m.ActiveConnections = len(s.connections)
	bans := []model.Ban{}
	now := time.Now()
	for _, b := range s.bans {
		if b.ExpiresAt.After(now) {
			bans = append(bans, b)
		}
	}
	return Snapshot{System: sys, Metrics: m, History: append([]Point{}, s.history...), Rules: p.Rules, Bans: bans, Events: append([]Event{}, s.events...), Connections: append([]Connection{}, s.connections...), Policy: p, Alerts: s.detector.Recent()}
}
func (s *Service) liveTick(now time.Time) {
	s.mu.RLock()
	r := s.runtime
	s.mu.RUnlock()
	if r == nil {
		return
	}
	snapshot, err := r.Snapshot()
	s.mu.Lock()
	if err != nil {
		s.liveStatus.Attached = false
		s.liveStatus.Health = []Health{{"Veri yolu", "error", err.Error()}}
		s.mu.Unlock()
		return
	}
	s.liveStatus = snapshot
	s.observedAt = now
	s.metrics = snapshot.Metrics
	s.connections = append([]Connection{}, snapshot.Connections...)
	for _, e := range snapshot.Events {
		s.detector.Observe(model.Packet{Timestamp: e.Timestamp, Source: e.Source, Destination: e.Destination, SourcePort: e.SourcePort, DestinationPort: e.DestinationPort, Protocol: e.Protocol, Length: e.Length}, true)
		s.events = append([]Event{e}, s.events...)
	}
	if len(s.events) > 300 {
		s.events = s.events[:300]
	}
	s.history = append(s.history, Point{now, s.metrics.PPS, s.metrics.BPS, s.metrics.DropPPS})
	if len(s.history) > 120 {
		s.history = s.history[len(s.history)-120:]
	}
	s.mu.Unlock()
	if err := s.store.SaveEvents(snapshot.Events); err != nil {
		s.mu.Lock()
		s.storageError = err.Error()
		s.mu.Unlock()
	}
}

// Caller owns s.mu. A failed kernel recovery must not be hidden behind a
// database error; the operator must see that the active state is uncertain.
func (s *Service) recoverPersistence(cause error, p model.Policy, bans []model.Ban) error {
	if s.runtime != nil {
		if rollbackErr := s.runtime.Apply(p, bans); rollbackErr != nil {
			cause = errors.Join(cause, fmt.Errorf("veri yolu geri alma başarısız: %w", rollbackErr))
			s.liveStatus.Attached = false
			s.liveStatus.Health = []Health{{"Kurtarma", "error", cause.Error()}}
		}
	}
	s.storageError = cause.Error()
	return cause
}
