// Package dataplane owns the real Linux XDP ingress filter. It does not emulate
// a kernel attach on other operating systems.
package dataplane

import (
	"context"
	"errors"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

var ErrUnsupported = errors.New("real XDP requires Linux; use the explicitly labelled laboratory backend on this platform")
var ErrForeignAttachment = errors.New("the interface XDP attachment no longer belongs to this WireWall instance")

type Options struct {
	ObjectPath string
	Interface  string
	Mode       string // native or generic, never a silent fallback
	OnEvent    func(Event)
}

type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type Snapshot struct {
	Attached           bool               `json:"attached"`
	Interface          string             `json:"interface"`
	Mode               string             `json:"mode"`
	PolicyVersion      uint64             `json:"policyVersion"`
	ProgramID          uint32             `json:"programId"`
	LinkID             uint32             `json:"linkId"`
	Counters           map[string]Counter `json:"counters"`
	Protocols          map[string]Counter `json:"protocols"`
	Services           map[uint32]Counter `json:"services"`
	SourceEntries      int                `json:"sourceEntries"`
	BanEntries         int                `json:"banEntries"`
	RetiredGenerations int                `json:"retiredGenerations"`
	CleanupError       string             `json:"cleanupError,omitempty"`
}

type Event struct {
	Time          time.Time    `json:"time"`
	PolicyVersion uint64       `json:"policyVersion"`
	RuleID        string       `json:"ruleId,omitempty"`
	Reason        string       `json:"reason"`
	Action        string       `json:"action"`
	WouldDrop     bool         `json:"wouldDrop"`
	Packet        model.Packet `json:"packet"`
}

var reasonNames = [...]string{
	"pass", "drop", "would_drop", "malformed", "banned", "rule_drop",
	"service_limit", "source_limit", "complex_packet", "capacity_fallback",
	"event_lost", "management",
	"byte_limit", "source_byte_limit",
	"service_stats_overflow",
}

type implementation interface {
	Start(context.Context, model.Policy) error
	Apply(model.Policy, []model.Ban) error
	Restore(model.Policy, []model.Ban) error
	Snapshot() (Snapshot, error)
	Close() error
}

type Manager struct{ backend implementation }

func New(options Options) (*Manager, error) {
	backend, err := newPlatformBackend(options)
	if err != nil {
		return nil, err
	}
	return &Manager{backend: backend}, nil
}

func (manager *Manager) Start(ctx context.Context, p model.Policy) error {
	return manager.backend.Start(ctx, p)
}

func (manager *Manager) Apply(p model.Policy, bans []model.Ban) error {
	return manager.backend.Apply(p, bans)
}

// Restore is the explicit recovery path for a previously captured policy.
// Ordinary Apply rejects a decreasing version; Restore permits it deliberately.
func (manager *Manager) Restore(p model.Policy, bans []model.Ban) error {
	return manager.backend.Restore(p, bans)
}

func (manager *Manager) Snapshot() (Snapshot, error) { return manager.backend.Snapshot() }
func (manager *Manager) Close() error                { return manager.backend.Close() }
