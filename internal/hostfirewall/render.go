// Package hostfirewall renders and manages only WireWall's dedicated nftables
// table. XDP_PASS is still subject to this stateful host policy.
package hostfirewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

const TableName = "wirewall"
const ownershipMarker = "managed-by-wirewall"

type Snapshot struct {
	Exists bool   `json:"exists"`
	Source string `json:"source,omitempty"`
}

// Render returns an idempotent transaction for the project-owned table only.
// Input on other interfaces is left to their existing host policy.
func Render(p model.Policy) (string, error) {
	if err := policy.Validate(p); err != nil {
		return "", err
	}
	var output strings.Builder
	output.WriteString("# WireWall stateful host policy; XDP observe mode does not disable this layer.\n")
	fmt.Fprintf(&output, "add table inet %s { comment %q; }\n", TableName, ownershipMarker)
	fmt.Fprintf(&output, "flush table inet %s\n", TableName)
	fmt.Fprintf(&output, "add chain inet %s protected_input\n", TableName)
	fmt.Fprintf(&output, "add chain inet %s input { type filter hook input priority -5; policy accept; }\n", TableName)
	fmt.Fprintf(&output, "add rule inet %s input iifname %q jump protected_input\n", TableName, p.Interface)
	add := func(expression string) {
		fmt.Fprintf(&output, "add rule inet %s protected_input %s\n", TableName, expression)
	}
	add("iifname \"lo\" counter accept comment \"loopback\"")
	if !p.Host.IPv6 {
		add("meta nfproto ipv6 counter drop comment \"ipv6-disabled-profile\"")
	}
	add("ct state invalid counter drop comment \"invalid\"")
	add("ct state established,related counter accept comment \"established-related\"")
	add("meta nfproto ipv4 ip protocol icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } counter accept comment \"icmp-errors-pmtud\"")
	add("meta nfproto ipv4 ip protocol icmp icmp type { echo-request, echo-reply } limit rate 10/second burst 20 packets counter accept comment \"icmp-echo-limited\"")
	if p.Host.IPv6 {
		add("meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept comment \"icmpv6-errors-pmtud\"")
		add("meta nfproto ipv6 meta l4proto ipv6-icmp ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } counter accept comment \"ipv6-neighbor-discovery\"")
		add("meta nfproto ipv6 ip6 saddr fe80::/10 meta l4proto ipv6-icmp ip6 hoplimit 255 icmpv6 type nd-router-advert counter accept comment \"ipv6-router-advertisement\"")
		add("meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { echo-request, echo-reply } limit rate 10/second burst 20 packets counter accept comment \"icmpv6-echo-limited\"")
	}
	management := append([]string(nil), p.ManagementCIDRs...)
	sort.Strings(management)
	for _, network := range management {
		prefix, _ := netip.ParsePrefix(network)
		if prefix.Addr().Is6() && !p.Host.IPv6 {
			continue
		}
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		add(fmt.Sprintf("%s saddr %s tcp dport %d ct state new tcp flags & (fin | syn | rst | ack) == syn counter accept comment \"management-new-syn\"", family, prefix.Masked(), p.ManagementPort))
	}
	var tcp []uint16
	for _, port := range p.Host.TCPPorts {
		// Management cannot silently become globally open via the general port list.
		if port != p.ManagementPort {
			tcp = append(tcp, port)
		}
	}
	if len(tcp) > 0 {
		add(fmt.Sprintf("tcp dport %s ct state new tcp flags & (fin | syn | rst | ack) == syn counter accept comment \"service-new-syn\"", portSet(tcp)))
	}
	if len(p.Host.UDPPorts) > 0 {
		add(fmt.Sprintf("udp dport %s ct state new counter accept comment \"udp-service\"", portSet(p.Host.UDPPorts)))
	}
	add("counter drop comment \"default-deny\"")
	return output.String(), nil
}

func portSet(ports []uint16) string {
	ports = append([]uint16(nil), ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = strconv.Itoa(int(port))
	}
	return "{ " + strings.Join(values, ", ") + " }"
}

func nft(ctx context.Context, input string, args ...string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("nftables operations require Linux; render is available on every platform")
	}
	command := exec.CommandContext(ctx, "nft", args...)
	if input != "" {
		command.Stdin = strings.NewReader(input)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	data, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return data, nil
}

func Capture(ctx context.Context) (Snapshot, error) {
	if runtime.GOOS != "linux" {
		return Snapshot{}, errors.New("nftables snapshot requires Linux")
	}
	// List all table names first: a missing table is normal; an unavailable nft
	// command or permission failure must never be interpreted as an empty ruleset.
	data, err := nft(ctx, "", "list", "tables")
	if err != nil {
		return Snapshot{}, err
	}
	exists := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "table inet "+TableName {
			exists = true
		}
	}
	if !exists {
		return Snapshot{}, nil
	}
	data, err = nft(ctx, "", "list", "table", "inet", TableName)
	if err != nil {
		return Snapshot{}, err
	}
	if !strings.Contains(string(data), "comment \""+ownershipMarker+"\"") {
		return Snapshot{}, errors.New("an existing inet wirewall table has no ownership marker; refusing to replace it")
	}
	return Snapshot{Exists: true, Source: string(data)}, nil
}

func Apply(ctx context.Context, p model.Policy, dryRun bool) error {
	transaction, err := Render(p)
	if err != nil {
		return err
	}
	if _, err := Capture(ctx); err != nil {
		return err
	}
	if _, err := nft(ctx, transaction, "--check", "--file", "-"); err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	_, err = nft(ctx, transaction, "--file", "-")
	return err
}

// Restore accepts only a captured project-owned table. It never flushes or
// restores any unrelated table. The complete replacement is one nft transaction.
func Restore(ctx context.Context, snapshot Snapshot) error {
	current, err := Capture(ctx)
	if err != nil {
		return err
	}
	if snapshot.Exists && !strings.Contains(snapshot.Source, "comment \""+ownershipMarker+"\"") {
		return errors.New("snapshot is not a WireWall-owned table")
	}
	var transaction strings.Builder
	if current.Exists {
		fmt.Fprintf(&transaction, "delete table inet %s\n", TableName)
	}
	if snapshot.Exists {
		transaction.WriteString(snapshot.Source)
	}
	if transaction.Len() == 0 {
		return nil
	}
	if _, err := nft(ctx, transaction.String(), "--check", "--file", "-"); err != nil {
		return err
	}
	_, err = nft(ctx, transaction.String(), "--file", "-")
	return err
}
