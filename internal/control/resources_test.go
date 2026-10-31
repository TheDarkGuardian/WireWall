package control

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestResourceCPUParserExcludesGuestDoubleCounting(t *testing.T) {
	counters, err := parseResourceCPU("cpu 10 2 3 50 5 4 1 7 9 1\ncpu0 10 2 3 50\n")
	if err != nil || counters.total != 82 || counters.idle != 55 {
		t.Fatalf("CPU=%+v error=%v", counters, err)
	}
	for _, text := range []string{"", "cpu0 1 2 3 4", "cpu 1 2 3", "cpu 1 2 -3 4", "cpu 1 bad 3 4", "cpu 18446744073709551615 1 0 0"} {
		if _, err := parseResourceCPU(text); err == nil {
			t.Fatalf("malformed CPU accepted: %q", text)
		}
	}
}

func TestResourceMemoryParserHasNoMemFreeApproximation(t *testing.T) {
	total, used, err := parseResourceMemory("MemTotal: 4096 kB\nMemFree: 1024 kB\nMemAvailable: 1536 kB\n")
	if err != nil || *total != 4096*1024 || *used != 2560*1024 {
		t.Fatalf("total=%v used=%v error=%v", total, used, err)
	}
	total, used, err = parseResourceMemory("MemTotal: 4096 kB\nMemFree: 1024 kB\n")
	if err == nil || total == nil || *total != 4096*1024 || used != nil || !strings.Contains(err.Error(), "MemAvailable") {
		t.Fatalf("missing MemAvailable fabricated used memory: total=%v used=%v error=%v", total, used, err)
	}
	for _, text := range []string{"", "MemTotal: 0 kB", "MemTotal: 1024 bytes", "MemTotal: -1 kB", "MemTotal: 18446744073709551615 kB", "MemTotal: 1 kB\nMemTotal: 2 kB", "MemTotal: 1 kB\nMemAvailable: 2 kB"} {
		if _, _, err := parseResourceMemory(text); err == nil {
			t.Fatalf("malformed memory accepted: %q", text)
		}
	}
}

func fixtureResourceSampler() (*ResourceSampler, map[string][]byte, *time.Time) {
	now := time.Unix(100, 0)
	files := map[string][]byte{
		"/proc/stat":    []byte("cpu 10 0 0 90 0 0 0 0\n"),
		"/proc/meminfo": []byte("MemTotal: 4096 kB\nMemAvailable: 1536 kB\n"),
		"/proc/sys/net/netfilter/nf_conntrack_count": []byte("12\n"),
		"/proc/sys/net/netfilter/nf_conntrack_max":   []byte("65536\n"),
	}
	sampler := &ResourceSampler{supported: true, now: func() time.Time { return now }, readFile: func(path string) ([]byte, error) {
		value, ok := files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return value, nil
	}}
	return sampler, files, &now
}

func TestResourceSamplerCPUIntervalsAndNullableStatus(t *testing.T) {
	sampler, files, now := fixtureResourceSampler()
	first := sampler.Sample()
	if !first.Available || first.CPUPercent != nil || first.MemoryUsedBytes == nil || *first.ConntrackCount != 12 || *first.ConntrackMax != 65536 {
		t.Fatalf("first sample=%+v", first)
	}
	*now = now.Add(time.Second)
	files["/proc/stat"] = []byte("cpu 40 0 0 150 10 0 0 0\n")
	second := sampler.Sample()
	// Delta total=100, idle+iowait=70, busy=30.
	if second.CPUPercent == nil || math.Abs(*second.CPUPercent-30) > 0.0001 {
		t.Fatalf("CPU delta=%+v", second.CPUPercent)
	}
	*second.CPUPercent = 999
	*second.ConntrackCount = 999
	cached := sampler.Sample()
	if *cached.CPUPercent != 30 || *cached.ConntrackCount != 12 {
		t.Fatal("returned pointers mutated cached sampler state")
	}
	*now = now.Add(time.Second)
	unchanged := sampler.Sample()
	if unchanged.CPUPercent != nil || !strings.Contains(unchanged.Detail, "henüz yeni") {
		t.Fatalf("zero CPU interval fabricated a percentage: %+v", unchanged)
	}
	*now = now.Add(time.Second)
	files["/proc/stat"] = []byte("cpu 1 0 0 9 0 0 0 0\n")
	reset := sampler.Sample()
	if reset.CPUPercent != nil || !strings.Contains(reset.Detail, "sıfırlandı") {
		t.Fatalf("counter reset produced a percentage: %+v", reset)
	}
	*now = now.Add(time.Second)
	files["/proc/stat"] = []byte("cpu 3 0 0 17 0 0 0 0\n")
	recovered := sampler.Sample()
	if recovered.CPUPercent == nil || *recovered.CPUPercent != 20 {
		t.Fatalf("counter reset did not rebaseline: %+v", recovered)
	}
}

func TestResourceSamplerWrapAndInconsistentCounterIntervals(t *testing.T) {
	sampler, files, now := fixtureResourceSampler()
	files["/proc/stat"] = []byte("cpu 18446744073709551500 0 0 0 0 0 0 0\n")
	sampler.Sample()
	*now = now.Add(time.Second)
	files["/proc/stat"] = []byte("cpu 2 0 0 1 0 0 0 0\n")
	wrapped := sampler.Sample()
	if wrapped.CPUPercent != nil || !strings.Contains(wrapped.Detail, "sıfırlandı") {
		t.Fatalf("wrapped counter accepted: %+v", wrapped)
	}
	// Total increases but idle delta exceeds total delta (other fields shrank).
	*now = now.Add(time.Second)
	files["/proc/stat"] = []byte("cpu 0 0 0 5 0 0 0 0\n")
	inconsistent := sampler.Sample()
	if inconsistent.CPUPercent != nil || !strings.Contains(inconsistent.Detail, "tutarsız") {
		t.Fatalf("inconsistent interval accepted: %+v", inconsistent)
	}
}

func TestResourceSamplerPartialAndUnsupportedDataStayNull(t *testing.T) {
	sampler, files, _ := fixtureResourceSampler()
	delete(files, "/proc/stat")
	delete(files, "/proc/sys/net/netfilter/nf_conntrack_count")
	files["/proc/sys/net/netfilter/nf_conntrack_max"] = []byte("not-a-number")
	files["/proc/meminfo"] = []byte("MemTotal: 1024 kB\nMemFree: 128 kB\n")
	partial := sampler.Sample()
	if !partial.Available || partial.CPUPercent != nil || partial.MemoryUsedBytes != nil || partial.MemoryTotalBytes == nil || partial.ConntrackCount != nil || partial.ConntrackMax != nil {
		t.Fatalf("partial resources fabricated values: %+v", partial)
	}
	unsupported := &ResourceSampler{supported: false, readFile: func(string) ([]byte, error) { panic("unsupported platform must not read procfs") }}
	status := unsupported.Sample()
	if status.Available || status.Detail == "" || status.CPUPercent != nil || status.MemoryUsedBytes != nil || status.MemoryTotalBytes != nil || status.ConntrackCount != nil || status.ConntrackMax != nil {
		t.Fatalf("unsupported resources=%+v", status)
	}
	raw, err := json.Marshal(status)
	if err != nil || !strings.Contains(string(raw), `"cpuPercent":null`) || !strings.Contains(string(raw), `"memoryUsedBytes":null`) {
		t.Fatalf("unavailable resources omitted/null contract changed: %s error=%v", raw, err)
	}
}

func TestResourceSamplerMissingProcfsAndConcurrentReaders(t *testing.T) {
	sampler := &ResourceSampler{supported: true, now: time.Now, readFile: func(string) ([]byte, error) { return nil, errors.New("unavailable") }}
	if got := sampler.Sample(); got.Available || got.Detail == "" {
		t.Fatalf("missing procfs=%+v", got)
	}
	sampler, _, _ = fixtureResourceSampler()
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 10; j++ {
				status := sampler.Sample()
				if !status.Available || status.CPUPercent != nil {
					t.Errorf("concurrent baseline=%+v", status)
				}
			}
		}()
	}
	wait.Wait()
}
