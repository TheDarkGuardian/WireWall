package control

import (
	"github.com/TheDarkGuardian/WireWall/internal/detection"
	"github.com/TheDarkGuardian/WireWall/internal/hostfirewall"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"time"
)

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}
type Health struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type System struct {
	Name               string         `json:"name"`
	Version            string         `json:"version"`
	Backend            string         `json:"backend"`
	Platform           string         `json:"platform"`
	Hostname           string         `json:"hostname"`
	Interface          string         `json:"interface"`
	XDPMode            string         `json:"xdpMode"`
	Attached           bool           `json:"attached"`
	Mode               string         `json:"mode"`
	PolicyVersion      uint64         `json:"policyVersion"`
	StartedAt          time.Time      `json:"startedAt"`
	ObservedAt         time.Time      `json:"observedAt"`
	UptimeSeconds      int64          `json:"uptimeSeconds"`
	Simulated          bool           `json:"simulated"`
	Scenario           string         `json:"scenario"`
	ActivationPending  bool           `json:"activationPending"`
	ActivationDeadline time.Time      `json:"activationDeadline,omitempty"`
	Resources          ResourceStatus `json:"resources"`
	Capabilities       []Capability   `json:"capabilities"`
	Health             []Health       `json:"health"`
}
type ReasonCount struct {
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}
type ProtocolCount struct {
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
}
type ServiceCount struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
}
type Metrics struct {
	ReceivedPackets      uint64                `json:"receivedPackets"`
	PassedPackets        uint64                `json:"passedPackets"`
	DroppedPackets       uint64                `json:"droppedPackets"`
	WouldDropPackets     uint64                `json:"wouldDropPackets"`
	ReceivedBytes        uint64                `json:"receivedBytes"`
	PPS                  float64               `json:"pps"`
	BPS                  float64               `json:"bps"`
	DropPPS              float64               `json:"dropPps"`
	ActiveConnections    int                   `json:"activeConnections"`
	BlockedSources       int                   `json:"blockedSources"`
	MapCapacityFailures  uint64                `json:"mapCapacityFailures"`
	EventDrops           uint64                `json:"eventDrops"`
	Reasons              []ReasonCount         `json:"reasons"`
	Protocols            []ProtocolCount       `json:"protocols"`
	Services             []ServiceCount        `json:"services"`
	ServiceStatsOverflow uint64                `json:"serviceStatsOverflow"`
	HostFirewall         hostfirewall.Counters `json:"hostFirewall"`
}
type Point struct {
	Timestamp time.Time `json:"timestamp"`
	PPS       float64   `json:"pps"`
	BPS       float64   `json:"bps"`
	DropPPS   float64   `json:"dropPps"`
}
type Event struct {
	ID              string    `json:"id"`
	PolicyVersion   uint64    `json:"policyVersion,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Source          string    `json:"source"`
	Destination     string    `json:"destination"`
	SourcePort      uint16    `json:"sourcePort"`
	DestinationPort uint16    `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	Length          uint32    `json:"length"`
	Action          string    `json:"action"`
	Reason          string    `json:"reason"`
	RuleID          string    `json:"ruleId,omitempty"`
	WouldDrop       bool      `json:"wouldDrop"`
	Simulated       bool      `json:"simulated"`
}
type Connection struct {
	ID                  string    `json:"id"`
	Source              string    `json:"source"`
	Destination         string    `json:"destination"`
	SourcePort          uint16    `json:"sourcePort"`
	DestinationPort     uint16    `json:"destinationPort"`
	Protocol            string    `json:"protocol"`
	State               string    `json:"state"`
	Direction           string    `json:"direction"`
	Packets             uint64    `json:"packets"`
	Bytes               uint64    `json:"bytes"`
	AccountingAvailable bool      `json:"accountingAvailable"`
	ObservedAt          time.Time `json:"observedAt"`
	Simulated           bool      `json:"simulated"`
}
type Snapshot struct {
	Alerts      []detection.Alert `json:"alerts"`
	System      System            `json:"system"`
	Metrics     Metrics           `json:"metrics"`
	History     []Point           `json:"history"`
	Rules       []model.Rule      `json:"rules"`
	Bans        []model.Ban       `json:"bans"`
	Events      []Event           `json:"events"`
	Connections []Connection      `json:"connections"`
	Policy      model.Policy      `json:"policy"`
}
type Audit struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}
