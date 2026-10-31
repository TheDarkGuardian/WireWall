// Package detection produces bounded, observational traffic warnings. It does
// not block traffic or treat a heuristic warning as a proven attack.
package detection

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

const (
	MaxTrackedPorts = 64
	Cooldown        = 30 * time.Second
)

type Options struct {
	Window         time.Duration
	Threshold      int
	SourceCapacity int
	MaxAlerts      int
	Clock          func() time.Time
}

type Alert struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Source        string    `json:"source"`
	Destination   string    `json:"destination"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	Message       string    `json:"message"`
	UniquePorts   int       `json:"uniquePorts"`
	WindowSeconds float64   `json:"windowSeconds"`
	Sampled       bool      `json:"sampled"`
}

type Stats struct {
	Sources            int    `json:"sources"`
	SourceCapacity     int    `json:"sourceCapacity"`
	Alerts             int    `json:"alerts"`
	ObservedTCPPackets uint64 `json:"observedTcpPackets"`
	CapacityDrops      uint64 `json:"capacityDrops"`
	PortSetSaturations uint64 `json:"portSetSaturations"`
}

type flowKey struct{ source, destination string }

type portWindow struct {
	started, seen time.Time
	ports         map[uint16]struct{}
	sampled       bool
	alerted       bool
	lastAlert     time.Time
	hasLastAlert  bool
}

type Detector struct {
	mu             sync.Mutex
	window         time.Duration
	threshold      int
	capacity       int
	maxAlerts      int
	clock          func() time.Time
	entries        map[flowKey]*portWindow
	alerts         []Alert
	nextSweep      time.Time
	sweepInterval  time.Duration
	observed       uint64
	capacityDrops  uint64
	portSaturation uint64
}

var alertSequence atomic.Uint64

// New defaults to 20 unique TCP destination ports per source/destination pair
// in ten seconds, with 1,024 tracked pairs and 100 retained alerts. Thresholds
// above the bounded 64-port set are clamped to 64. Invalid nonpositive options
// use defaults. Idle table sweeps occur at most once per second by default,
// rather than scanning the source table for every packet.
func New(options Options) *Detector {
	if options.Window <= 0 {
		options.Window = 10 * time.Second
	}
	if options.Threshold <= 0 {
		options.Threshold = 20
	}
	if options.Threshold > MaxTrackedPorts {
		options.Threshold = MaxTrackedPorts
	}
	if options.SourceCapacity <= 0 {
		options.SourceCapacity = 1024
	}
	if options.MaxAlerts <= 0 {
		options.MaxAlerts = 100
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	interval := time.Second
	if options.Window < interval {
		interval = options.Window
	}
	return &Detector{
		window: options.Window, threshold: options.Threshold, capacity: options.SourceCapacity,
		maxAlerts: options.MaxAlerts, clock: options.Clock, entries: map[flowKey]*portWindow{},
		alerts: []Alert{}, sweepInterval: interval,
	}
}

// Observe consumes a packet description. Packet.Timestamp is metadata and is
// never trusted for time windows or cooldowns. Each window tracks at most 64
// ports; once capacity is full, new pairs are ignored without evicting active
// pairs or resetting their evidence/cooldown. This is a warning mechanism, not
// a distributed scan detector or a rate-limit security guarantee.
func (detector *Detector) Observe(packet model.Packet, sampled bool) []Alert {
	if packet.Protocol != "tcp" {
		return nil
	}
	source, err := netip.ParseAddr(packet.Source)
	if err != nil || source.Zone() != "" || source.IsUnspecified() || source.IsMulticast() {
		return nil
	}
	destination, err := netip.ParseAddr(packet.Destination)
	if err != nil || destination.Zone() != "" || destination.IsUnspecified() || destination.IsMulticast() {
		return nil
	}
	source, destination = source.Unmap(), destination.Unmap()
	if source.BitLen() != destination.BitLen() {
		return nil
	}
	key := flowKey{source: source.String(), destination: destination.String()}
	detector.mu.Lock()
	defer detector.mu.Unlock()
	now := detector.clock()
	detector.observed++
	detector.sweep(now)
	entry := detector.entries[key]
	if entry == nil {
		if len(detector.entries) >= detector.capacity {
			detector.capacityDrops++
			return nil
		}
		entry = &portWindow{started: now, seen: now, ports: make(map[uint16]struct{}, MaxTrackedPorts)}
		detector.entries[key] = entry
	}
	if now.Before(entry.started) || now.Sub(entry.started) >= detector.window {
		entry.started = now
		entry.ports = make(map[uint16]struct{}, MaxTrackedPorts)
		entry.sampled = false
		entry.alerted = false
	}
	entry.seen = now
	entry.sampled = entry.sampled || sampled
	if _, exists := entry.ports[packet.DestinationPort]; !exists {
		if len(entry.ports) < MaxTrackedPorts {
			entry.ports[packet.DestinationPort] = struct{}{}
		} else {
			detector.portSaturation++
		}
	}
	if entry.alerted || len(entry.ports) < detector.threshold {
		return nil
	}
	if entry.hasLastAlert && now.Sub(entry.lastAlert) < Cooldown {
		return nil
	}
	entry.alerted = true
	entry.lastAlert = now
	entry.hasLastAlert = true
	prefix := "Gözlemde"
	if entry.sampled {
		prefix = "Örneklenen trafikte"
	}
	alert := Alert{
		ID: fmt.Sprintf("scan-%x-%x", now.UnixNano(), alertSequence.Add(1)), Timestamp: now.UTC(),
		Source: key.source, Destination: key.destination, Type: "port_scan", Severity: "warning",
		Message:     fmt.Sprintf("%s %.3g saniyelik pencerede %d farklı TCP hedef portu görüldü. Olası port taraması; otomatik engelleme yapılmadı.", prefix, detector.window.Seconds(), len(entry.ports)),
		UniquePorts: len(entry.ports), WindowSeconds: detector.window.Seconds(), Sampled: entry.sampled,
	}
	detector.alerts = append(detector.alerts, alert)
	if len(detector.alerts) > detector.maxAlerts {
		copy(detector.alerts, detector.alerts[len(detector.alerts)-detector.maxAlerts:])
		detector.alerts = detector.alerts[:detector.maxAlerts]
	}
	return []Alert{alert}
}

func (detector *Detector) sweep(now time.Time) {
	if !detector.nextSweep.IsZero() && now.Before(detector.nextSweep) {
		return
	}
	detector.nextSweep = now.Add(detector.sweepInterval)
	for key, entry := range detector.entries {
		idle := now.Sub(entry.seen) >= detector.window
		cooldownPassed := !entry.hasLastAlert || now.Sub(entry.lastAlert) >= Cooldown
		if idle && cooldownPassed {
			delete(detector.entries, key)
		}
	}
}

// Recent returns newest-first history; callers cannot mutate detector storage.
func (detector *Detector) Recent() []Alert {
	detector.mu.Lock()
	defer detector.mu.Unlock()
	result := make([]Alert, len(detector.alerts))
	for i, alert := range detector.alerts {
		result[len(result)-1-i] = alert
	}
	return result
}

func (detector *Detector) Stats() Stats {
	detector.mu.Lock()
	defer detector.mu.Unlock()
	return Stats{Sources: len(detector.entries), SourceCapacity: detector.capacity, Alerts: len(detector.alerts), ObservedTCPPackets: detector.observed, CapacityDrops: detector.capacityDrops, PortSetSaturations: detector.portSaturation}
}
