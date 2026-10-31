package control

import (
	"testing"
	"time"
)

func TestConntrackOriginalTupleAndAccounting(t *testing.T) {
	text := "tcp 6 431999 ESTABLISHED src=198.51.100.10 dst=203.0.113.10 sport=41000 dport=443 packets=7 bytes=700 src=203.0.113.10 dst=198.51.100.10 sport=443 dport=41000 packets=8 bytes=900 [ASSURED] mark=0 use=1\n" +
		"udp 17 29 src=192.0.2.10 dst=203.0.113.10 sport=50000 dport=53 src=203.0.113.10 dst=192.0.2.10 sport=53 dport=50000 [ASSURED] mark=0 use=1\n" +
		"invalid line\n"
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	flows := parseConntrack(text, now)
	if len(flows) != 2 {
		t.Fatalf("flows %d", len(flows))
	}
	tcp := flows[0]
	if tcp.Source != "198.51.100.10" || tcp.SourcePort != 41000 || tcp.DestinationPort != 443 || tcp.Packets != 7 || tcp.Bytes != 700 || !tcp.AccountingAvailable || tcp.Simulated {
		t.Fatalf("wrong original tuple/accounting: %+v", tcp)
	}
	if !tcp.ObservedAt.Equal(now) {
		t.Fatal("observation timestamp must be supplied control-plane time")
	}
	if flows[1].AccountingAvailable || flows[1].State != "TRACKED" {
		t.Fatalf("disabled accounting was not identified: %+v", flows[1])
	}
}
func TestConntrackBoundedResults(t *testing.T) {
	text := ""
	for i := 0; i < 300; i++ {
		text += "udp 17 29 src=192.0.2.10 dst=203.0.113.10 sport=50000 dport=53\n"
	}
	if len(parseConntrack(text, time.Now())) != 256 {
		t.Fatal("conntrack result budget not enforced")
	}
	b := &limitedBuffer{max: 4}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("5")); err == nil {
		t.Fatal("output budget not enforced")
	}
}
