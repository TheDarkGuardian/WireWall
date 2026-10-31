// Package model contains the portable WireWall policy and API contracts.
package model

import "time"

// Rule fields are combined with AND. The first enabled matching rule wins.
// A pass verdict only forwards a packet to the host firewall; it never bypasses
// nftables or claims that the packet belongs to an established connection.
type Rule struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	Priority        int    `json:"priority"`
	Action          string `json:"action"`
	Protocol        string `json:"protocol"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	MinPacketBytes  uint32 `json:"minPacketBytes"`
	MaxPacketBytes  uint32 `json:"maxPacketBytes"`
	PPS             uint64 `json:"pps"`
	Burst           uint64 `json:"burst"`
	SourcePPS       uint64 `json:"sourcePps,omitempty"`
	SourceBurst     uint64 `json:"sourceBurst,omitempty"`
	// Byte budgets use IP bytes/second and IP bytes, not bits/second or L2 wire size.
	BPS             uint64 `json:"bps,omitempty"`
	ByteBurst       uint64 `json:"byteBurst,omitempty"`
	SourceBPS       uint64 `json:"sourceBps,omitempty"`
	SourceByteBurst uint64 `json:"sourceByteBurst,omitempty"`
	TCPFlags        string `json:"tcpFlags,omitempty"`
}

type HostPolicy struct {
	TCPPorts []uint16 `json:"tcpPorts"`
	UDPPorts []uint16 `json:"udpPorts"`
	IPv6     bool     `json:"ipv6"`
}

type Policy struct {
	Version         uint64     `json:"version"`
	Mode            string     `json:"mode"`
	Interface       string     `json:"interface"`
	XDPMode         string     `json:"xdpMode"`
	ManagementCIDRs []string   `json:"managementCidrs"`
	ManagementPort  uint16     `json:"managementPort"`
	Rules           []Rule     `json:"rules"`
	Host            HostPolicy `json:"host"`
}

type Ban struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Packet is a synthetic packet description for the portable laboratory path.
// It does not carry TCP state: that belongs to the real host conntrack layer.
type Packet struct {
	Timestamp       time.Time `json:"timestamp"`
	Source          string    `json:"source"`
	Destination     string    `json:"destination"`
	SourcePort      uint16    `json:"sourcePort"`
	DestinationPort uint16    `json:"destinationPort"`
	Protocol        string    `json:"protocol"`
	Length          uint32    `json:"length"`
	TCPFlags        string    `json:"tcpFlags,omitempty"`
}

type Decision struct {
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	RuleID    string `json:"ruleId,omitempty"`
	WouldDrop bool   `json:"wouldDrop"`
}
