//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"golang.org/x/sys/unix"
)

type linuxBackend struct {
	mu           sync.Mutex
	options      Options
	collection   *ebpf.Collection
	policySpec   *ebpf.MapSpec
	attached     link.Link
	reader       *ringbuf.Reader
	policy       model.Policy
	compiled     compiledPolicy
	lastPolicy   []byte
	closed       bool
	programID    uint32
	linkID       uint32
	retired      map[uint64]bool
	activeBans   map[banKey]uint64
	cleanupError string
	ruleIDs      map[uint64][]string
}

type banKey struct {
	Version         uint64
	Family, Padding uint32
	Address         [16]byte
}
type sourceKey struct {
	Version      uint64
	Slot, Family uint32
	Address      [16]byte
}
type bucketKey struct {
	Version       uint64
	Slot, Padding uint32
}
type bucketValue struct {
	Lock, Padding      uint32
	UpdatedNS, Credits uint64
	ByteCredits        uint64
}
type kernelEvent struct {
	MonotonicNS, Version                                    uint64
	RuleIndex, Reason, Dropped, WouldDrop, Family, Protocol uint32
	Source, Destination                                     [16]byte
	SourcePort, DestinationPort                             uint16
	Length                                                  uint32
}

func newPlatformBackend(options Options) (implementation, error) {
	if options.ObjectPath == "" {
		options.ObjectPath = "bpf/wirewall_bpfel.o"
	}
	return &linuxBackend{options: options, ruleIDs: make(map[uint64][]string), retired: make(map[uint64]bool)}, nil
}

func (backend *linuxBackend) Start(ctx context.Context, p model.Policy) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return errors.New("dataplane manager is closed")
	}
	if backend.collection != nil {
		return errors.New("dataplane is already started")
	}
	if _, err := compilePolicy(p); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("XDP startup requires root/CAP_BPF and CAP_NET_ADMIN; start via the documented Linux service")
	}
	ifaceName := backend.options.Interface
	if ifaceName == "" {
		ifaceName = p.Interface
	}
	if ifaceName != p.Interface {
		return errors.New("interface override and policy interface must match")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("network interface: %w", err)
	}
	queryContext, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	existingID, err := CurrentProgramID(queryContext, ifaceName)
	queryCancel()
	if err != nil {
		return fmt.Errorf("inspect current XDP attachment: %w", err)
	}
	if existingID != 0 {
		return errors.New("the interface already has an XDP program; refusing to replace or chain it")
	}
	mode := backend.options.Mode
	if mode == "" {
		mode = p.XDPMode
	}
	if mode != "native" && mode != "generic" {
		return errors.New("XDP mode must be native or generic")
	}
	if mode != p.XDPMode {
		return errors.New("XDP mode override and policy mode must match")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("BPF memlock setup: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(backend.options.ObjectPath)
	if err != nil {
		return fmt.Errorf("load compiled BPF object (run scripts/linux/build.sh on Ubuntu): %w", err)
	}
	outer := spec.Maps["policies"]
	if outer == nil || outer.InnerMap == nil || outer.InnerMap.ValueSize != policySize {
		return errors.New("BPF policy map ABI does not match this WireWall build")
	}
	backend.policySpec = outer.InnerMap.Copy()
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("kernel rejected BPF collection: %w", err)
	}
	backend.collection = collection
	cleanup := func() { collection.Close(); backend.collection = nil }
	for _, name := range []string{"policies", "bans", "counters", "protocol_counts", "service_counts", "service_buckets", "source_buckets", "events", "readers"} {
		if collection.Maps[name] == nil {
			cleanup()
			return fmt.Errorf("BPF object is missing map %s", name)
		}
	}
	if collection.Programs["wirewall_xdp"] == nil {
		cleanup()
		return errors.New("BPF object is missing wirewall_xdp program")
	}
	if err := backend.applyLocked(p, nil, false); err != nil {
		cleanup()
		return err
	}
	flags := link.XDPDriverMode
	if mode == "generic" {
		flags = link.XDPGenericMode
	}
	xdpLink, err := link.AttachXDP(link.XDPOptions{Program: collection.Programs["wirewall_xdp"], Interface: iface.Index, Flags: flags})
	if err != nil {
		cleanup()
		return fmt.Errorf("attach XDP %s to %s (existing program is not replaced): %w", mode, ifaceName, err)
	}
	backend.attached = xdpLink
	programInfo, err := collection.Programs["wirewall_xdp"].Info()
	if err != nil {
		_ = xdpLink.Close()
		backend.attached = nil
		cleanup()
		return fmt.Errorf("inspect loaded program identity: %w", err)
	}
	programID, available := programInfo.ID()
	if !available || programID == 0 {
		_ = xdpLink.Close()
		backend.attached = nil
		cleanup()
		return errors.New("kernel did not expose the loaded XDP program ID")
	}
	linkInfo, err := xdpLink.Info()
	if err != nil || linkInfo.ID == 0 {
		_ = xdpLink.Close()
		backend.attached = nil
		cleanup()
		return errors.New("kernel did not expose an XDP link ID for independent recovery")
	}
	backend.programID, backend.linkID = uint32(programID), uint32(linkInfo.ID)
	queryContext, queryCancel = context.WithTimeout(ctx, 3*time.Second)
	actualID, queryErr := CurrentProgramID(queryContext, ifaceName)
	queryCancel()
	if queryErr != nil || actualID != backend.programID {
		_ = xdpLink.Close()
		backend.attached = nil
		cleanup()
		return errors.New("could not verify the attached XDP program identity")
	}
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		_ = xdpLink.Close()
		backend.attached = nil
		cleanup()
		return fmt.Errorf("open XDP event reader: %w", err)
	}
	backend.reader = reader
	go backend.readEvents(reader)
	go func() { <-ctx.Done(); _ = backend.Close() }()
	return nil
}

func monotonicNS() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return uint64(ts.Nano()), nil
}

func (backend *linuxBackend) Apply(p model.Policy, bans []model.Ban) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.collection == nil || backend.closed {
		return errors.New("XDP is not running")
	}
	if p.Interface != backend.policy.Interface || p.XDPMode != backend.policy.XDPMode {
		return errors.New("changing interface or native/generic mode requires a controlled restart")
	}
	return backend.applyLocked(p, bans, false)
}

func (backend *linuxBackend) Restore(p model.Policy, bans []model.Ban) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.collection == nil || backend.closed {
		return errors.New("XDP is not running")
	}
	if p.Interface != backend.policy.Interface || p.XDPMode != backend.policy.XDPMode {
		return errors.New("restore cannot move an XDP attachment")
	}
	return backend.applyLocked(p, bans, true)
}

func (backend *linuxBackend) applyLocked(p model.Policy, banList []model.Ban, restoring bool) (applyErr error) {
	compiled, err := compilePolicy(p)
	if err != nil {
		return err
	}
	data, err := compiled.value.marshal()
	if err != nil {
		return err
	}
	if !restoring && backend.policy.Version > p.Version {
		return errors.New("policy versions must not decrease; use explicit Restore for recovery")
	}
	if !restoring && p.Version == backend.policy.Version && !bytes.Equal(backend.lastPolicy, data) {
		return errors.New("changed policy must have a new version")
	}
	if backend.retired == nil {
		backend.retired = make(map[uint64]bool)
	}
	if backend.policy.Version != 0 {
		backend.pruneMapsLocked(backend.policy.Version, backend.activeBans)
		if p.Version != backend.policy.Version && !backend.retired[p.Version] && len(backend.retired) >= maxRetiredGenerations {
			return errors.New("policy activation deferred: retired generations still have active readers")
		}
	}
	banMap := backend.collection.Maps["bans"]
	if len(banList) > 4096 {
		return errors.New("at most 4096 ban records are supported")
	}
	bootNow, err := monotonicNS()
	if err != nil {
		return fmt.Errorf("monotonic clock: %w", err)
	}
	now := time.Now()
	newBans := make(map[banKey]uint64, len(banList))
	for _, ban := range banList {
		address, err := netip.ParseAddr(ban.Address)
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return fmt.Errorf("invalid exact ban address %q", ban.Address)
		}
		if !ban.ExpiresAt.After(now) {
			continue
		}
		remaining := ban.ExpiresAt.Sub(now)
		if remaining > 30*24*time.Hour {
			return errors.New("ban expiry exceeds 30 days")
		}
		key := banKey{Version: p.Version}
		if address.Is4() {
			key.Family = 4
			v := address.As4()
			copy(key.Address[:4], v[:])
		} else {
			key.Family = 6
			key.Address = address.As16()
		}
		newBans[key] = bootNow + uint64(remaining)
	}
	// Prepare new-generation bans before publishing the policy. For a ban-only
	// edit of the current generation each exact-key change is atomic; the whole
	// set is not advertised as one global atomic transaction.
	type previousBan struct {
		value  uint64
		exists bool
	}
	touched := make(map[banKey]previousBan, len(newBans))
	defer func() {
		if applyErr == nil {
			return
		}
		for key, previous := range touched {
			if previous.exists {
				_ = banMap.Put(key, previous.value)
			} else {
				_ = banMap.Delete(key)
			}
		}
	}()
	for key, expiry := range newBans {
		var previous uint64
		lookupErr := banMap.Lookup(key, &previous)
		if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("read prior ban: %w", lookupErr)
		}
		touched[key] = previousBan{value: previous, exists: lookupErr == nil}
		if err := banMap.Put(key, expiry); err != nil {
			return fmt.Errorf("stage ban map: %w", err)
		}
	}
	inner, err := ebpf.NewMap(backend.policySpec)
	if err != nil {
		return fmt.Errorf("create inactive policy map: %w", err)
	}
	defer inner.Close()
	zero := uint32(0)
	if err := inner.Put(zero, data); err != nil {
		return fmt.Errorf("stage complete policy: %w", err)
	}
	if err := backend.collection.Maps["policies"].Put(zero, inner); err != nil {
		return fmt.Errorf("publish policy map: %w", err)
	}
	previousVersion := backend.policy.Version
	backend.policy, backend.compiled, backend.lastPolicy = p, compiled, data
	backend.activeBans = newBans
	if previousVersion != 0 && previousVersion != p.Version {
		backend.retired[previousVersion] = true
	}
	delete(backend.retired, p.Version)
	ids := make([]string, len(compiled.rules))
	for i, rule := range compiled.rules {
		ids[i] = rule.ID
	}
	backend.ruleIDs[p.Version] = ids
	// Retired policy references remain valid under kernel RCU. Keep their ban
	// and bucket state too until every CPU has passed a quiescent observation.
	backend.pruneMapsLocked(p.Version, newBans)
	return nil
}

func (backend *linuxBackend) pruneMapsLocked(version uint64, currentBans map[banKey]uint64) {
	var readers []uint64
	if err := backend.collection.Maps["readers"].Lookup(uint32(0), &readers); err != nil {
		backend.cleanupError = fmt.Sprintf("read generation readers: %v", err)
		return
	}
	quiescent := readersQuiescent(readers)
	backend.cleanupError = ""
	var ban banKey
	var expiry uint64
	var removeBans []banKey
	iter := backend.collection.Maps["bans"].Iterate()
	for iter.Next(&ban, &expiry) {
		if ban.Version != version && quiescent {
			removeBans = append(removeBans, ban)
			continue
		}
		if _, exists := currentBans[ban]; ban.Version == version && !exists {
			removeBans = append(removeBans, ban)
		}
	}
	if err := iter.Err(); err != nil {
		backend.cleanupError = fmt.Sprintf("iterate retired bans: %v", err)
		return
	}
	for _, key := range removeBans {
		if err := backend.collection.Maps["bans"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			backend.cleanupError = fmt.Sprintf("remove retired ban: %v", err)
			return
		}
	}
	var service bucketKey
	var bucket bucketValue
	var removeServices []bucketKey
	iter = backend.collection.Maps["service_buckets"].Iterate()
	for iter.Next(&service, &bucket) {
		if quiescent && service.Version != version {
			removeServices = append(removeServices, service)
		}
	}
	if err := iter.Err(); err != nil {
		backend.cleanupError = fmt.Sprintf("iterate retired service buckets: %v", err)
		return
	}
	for _, key := range removeServices {
		if err := backend.collection.Maps["service_buckets"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			backend.cleanupError = fmt.Sprintf("remove retired service bucket: %v", err)
			return
		}
	}
	var source sourceKey
	var removeSources []sourceKey
	iter = backend.collection.Maps["source_buckets"].Iterate()
	for iter.Next(&source, &bucket) {
		if quiescent && source.Version != version {
			removeSources = append(removeSources, source)
		}
	}
	if err := iter.Err(); err != nil {
		backend.cleanupError = fmt.Sprintf("iterate retired source buckets: %v", err)
		return
	}
	for _, key := range removeSources {
		if err := backend.collection.Maps["source_buckets"].Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			backend.cleanupError = fmt.Sprintf("remove retired source bucket: %v", err)
			return
		}
	}
	if quiescent {
		clear(backend.retired)
	}
	for oldVersion := range backend.ruleIDs {
		if oldVersion+16 < version {
			delete(backend.ruleIDs, oldVersion)
		}
	}
}

func (backend *linuxBackend) Snapshot() (Snapshot, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	result := Snapshot{Attached: backend.attached != nil, Interface: backend.policy.Interface, Mode: backend.policy.XDPMode, PolicyVersion: backend.policy.Version, ProgramID: backend.programID, LinkID: backend.linkID, Counters: make(map[string]Counter)}
	if backend.collection == nil || backend.closed {
		return result, errors.New("XDP is not running")
	}
	backend.pruneMapsLocked(backend.policy.Version, backend.activeBans)
	result.RetiredGenerations, result.CleanupError = len(backend.retired), backend.cleanupError
	queryContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	actualID, err := CurrentProgramID(queryContext, backend.policy.Interface)
	cancel()
	if err != nil {
		return result, fmt.Errorf("verify active XDP attachment: %w", err)
	}
	result.Attached = actualID == backend.programID
	if !result.Attached {
		return result, ErrForeignAttachment
	}
	for i, name := range reasonNames {
		var perCPU []Counter
		key := uint32(i)
		if err := backend.collection.Maps["counters"].Lookup(key, &perCPU); err != nil {
			return result, fmt.Errorf("read counters: %w", err)
		}
		var total Counter
		for _, counter := range perCPU {
			total.Packets += counter.Packets
			total.Bytes += counter.Bytes
		}
		result.Counters[name] = total
	}
	result.Protocols = make(map[string]Counter)
	for i, name := range []string{"other", "tcp", "udp", "icmp", "icmpv6", "arp", "complex", "malformed"} {
		var values []Counter
		if err := backend.collection.Maps["protocol_counts"].Lookup(uint32(i), &values); err != nil {
			return result, fmt.Errorf("protocol counters: %w", err)
		}
		for _, value := range values {
			total := result.Protocols[name]
			total.Packets += value.Packets
			total.Bytes += value.Bytes
			result.Protocols[name] = total
		}
	}
	result.Services = make(map[uint32]Counter)
	var serviceKey uint32
	var serviceValues []Counter
	services := backend.collection.Maps["service_counts"].Iterate()
	for services.Next(&serviceKey, &serviceValues) {
		var total Counter
		for _, value := range serviceValues {
			total.Packets += value.Packets
			total.Bytes += value.Bytes
		}
		result.Services[serviceKey] = total
	}
	if err := services.Err(); err != nil {
		return result, fmt.Errorf("service counters: %w", err)
	}
	var source sourceKey
	var bucket bucketValue
	iterator := backend.collection.Maps["source_buckets"].Iterate()
	for iterator.Next(&source, &bucket) {
		if source.Version == result.PolicyVersion {
			result.SourceEntries++
		}
	}
	if err := iterator.Err(); err != nil {
		return result, err
	}
	var ban banKey
	var expiry uint64
	now, err := monotonicNS()
	if err != nil {
		return result, err
	}
	iterator = backend.collection.Maps["bans"].Iterate()
	for iterator.Next(&ban, &expiry) {
		if ban.Version == result.PolicyVersion && expiry > now {
			result.BanEntries++
		}
	}
	return result, iterator.Err()
}

// CurrentProgramID queries iproute2 JSON (no shell interpolation). Multiple XDP
// attachments are intentionally rejected rather than guessed by recovery code.
func CurrentProgramID(ctx context.Context, iface string) (uint32, error) {
	if _, err := net.InterfaceByName(iface); err != nil {
		return 0, err
	}
	command := exec.CommandContext(ctx, "ip", "-j", "link", "show", "dev", iface)
	data, err := command.Output()
	if err != nil {
		return 0, fmt.Errorf("ip link identity query: %w", err)
	}
	var links []struct {
		XDP *struct {
			Mode uint32 `json:"mode"`
			Prog struct {
				ID uint32 `json:"id"`
			} `json:"prog"`
			Attached []struct {
				Prog struct {
					ID uint32 `json:"id"`
				} `json:"prog"`
			} `json:"attached"`
		} `json:"xdp"`
	}
	if err := json.Unmarshal(data, &links); err != nil || len(links) != 1 {
		return 0, errors.New("unexpected iproute2 link JSON")
	}
	if links[0].XDP == nil {
		return 0, nil
	}
	xdp := links[0].XDP
	if len(xdp.Attached) > 1 {
		return 0, errors.New("multiple XDP attachments are present; refusing ambiguous ownership")
	}
	if xdp.Prog.ID != 0 {
		return xdp.Prog.ID, nil
	}
	if len(xdp.Attached) == 1 {
		return xdp.Attached[0].Prog.ID, nil
	}
	if xdp.Mode != 0 {
		return 0, errors.New("XDP attachment exists but iproute2 did not expose its program identity")
	}
	return 0, nil
}

// DetachOwned is for the independent rollback process. Link identity prevents
// detaching an unrelated program if another administrator changed the interface.
func DetachOwned(ctx context.Context, iface string, expectedProgramID, expectedLinkID uint32) error {
	if expectedProgramID == 0 || expectedLinkID == 0 {
		return errors.New("program and link identity are required for recovery")
	}
	actualID, err := CurrentProgramID(ctx, iface)
	if err != nil {
		return err
	}
	if actualID == 0 {
		return nil
	} // Process exit may already have closed its link.
	if actualID != expectedProgramID {
		return ErrForeignAttachment
	}
	owned, err := link.NewFromID(link.ID(expectedLinkID))
	if err != nil {
		return fmt.Errorf("open recovery link: %w", err)
	}
	defer owned.Close()
	info, err := owned.Info()
	if err != nil {
		return err
	}
	if uint32(info.Program) != expectedProgramID {
		return ErrForeignAttachment
	}
	xdpInfo := info.XDP()
	ifaceInfo, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if xdpInfo == nil || xdpInfo.Ifindex != uint32(ifaceInfo.Index) {
		return ErrForeignAttachment
	}
	return owned.Detach()
}

func (backend *linuxBackend) readEvents(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			return
		}
		var raw kernelEvent
		if len(record.RawSample) != binary.Size(raw) || binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw) != nil {
			continue
		}
		backend.mu.Lock()
		callback := backend.options.OnEvent
		ids := backend.ruleIDs[raw.Version]
		var ruleID string
		if uint64(raw.RuleIndex) < uint64(len(ids)) {
			ruleID = ids[raw.RuleIndex]
		}
		backend.mu.Unlock()
		if callback == nil {
			continue
		}
		reason := "unknown"
		if raw.Reason < uint32(len(reasonNames)) {
			reason = reasonNames[raw.Reason]
		}
		now := time.Now().UTC()
		action := "pass"
		if raw.Dropped != 0 {
			action = "drop"
		}
		protocol := map[uint32]string{1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}[raw.Protocol]
		if protocol == "" {
			protocol = "other"
		}
		packet := model.Packet{Timestamp: now, Source: eventAddress(raw.Source, raw.Family), Destination: eventAddress(raw.Destination, raw.Family), SourcePort: raw.SourcePort, DestinationPort: raw.DestinationPort, Protocol: protocol, Length: raw.Length}
		callback(Event{Time: now, PolicyVersion: raw.Version, RuleID: ruleID, Reason: reason, Action: action, WouldDrop: raw.WouldDrop != 0, Packet: packet})
	}
}

func eventAddress(address [16]byte, family uint32) string {
	if family == 4 {
		var value [4]byte
		copy(value[:], address[:4])
		return netip.AddrFrom4(value).String()
	}
	if family == 6 {
		return netip.AddrFrom16(address).String()
	}
	return ""
}

func (backend *linuxBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil
	}
	backend.closed = true
	if backend.reader != nil {
		_ = backend.reader.Close()
	}
	var err error
	if backend.attached != nil {
		err = backend.attached.Close()
		backend.attached = nil
	}
	if backend.collection != nil {
		backend.collection.Close()
		backend.collection = nil
	}
	return err
}
