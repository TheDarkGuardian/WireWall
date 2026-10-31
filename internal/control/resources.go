package control

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ResourceStatus contains actual host observations only. A nil field is
// unavailable or still waiting for a measurement interval, never a synthetic
// zero. CPU busy time excludes idle/iowait and includes steal time: on a VM,
// vCPU time withheld by the hypervisor is therefore visible as pressure.
type ResourceStatus struct {
	CPUPercent       *float64 `json:"cpuPercent"`
	MemoryUsedBytes  *uint64  `json:"memoryUsedBytes"`
	MemoryTotalBytes *uint64  `json:"memoryTotalBytes"`
	ConntrackCount   *uint64  `json:"conntrackCount"`
	ConntrackMax     *uint64  `json:"conntrackMax"`
	Available        bool     `json:"available"`
	Detail           string   `json:"detail"`
}

type cpuResourceCounters struct {
	total uint64
	idle  uint64
}

// ResourceSampler reads Linux procfs without executing a command, changing a
// kernel setting or requiring root. Its cache avoids misleading zero-length
// CPU intervals when several HTTP/SSE clients request snapshots concurrently.
type ResourceSampler struct {
	mu          sync.Mutex
	supported   bool
	readFile    func(string) ([]byte, error)
	now         func() time.Time
	previous    cpuResourceCounters
	hasPrevious bool
	lastSample  time.Time
	lastStatus  ResourceStatus
}

func NewResourceSampler() *ResourceSampler {
	return &ResourceSampler{supported: runtime.GOOS == "linux", readFile: readResourceFile, now: time.Now}
}

func (sampler *ResourceSampler) Sample() ResourceStatus {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	if !sampler.supported {
		return ResourceStatus{Detail: "Gerçek host kaynak ölçümleri yalnız Linux procfs üzerinde kullanılabilir."}
	}
	now := sampler.now()
	if !sampler.lastSample.IsZero() {
		age := now.Sub(sampler.lastSample)
		if age >= 0 && age < 250*time.Millisecond {
			return cloneResourceStatus(sampler.lastStatus)
		}
	}
	status := ResourceStatus{}
	var detail []string
	if data, err := sampler.readFile("/proc/stat"); err != nil {
		detail = append(detail, "CPU sayaçları okunamadı.")
	} else if current, err := parseResourceCPU(string(data)); err != nil {
		detail = append(detail, "CPU sayacı geçersiz: "+err.Error())
	} else {
		if !sampler.hasPrevious {
			detail = append(detail, "CPU için ilk ölçüm aralığı bekleniyor.")
		} else if current.total < sampler.previous.total || current.idle < sampler.previous.idle {
			detail = append(detail, "CPU sayaçları sıfırlandı; yeni ölçüm aralığı bekleniyor.")
		} else {
			total := current.total - sampler.previous.total
			idle := current.idle - sampler.previous.idle
			if total == 0 {
				detail = append(detail, "CPU için henüz yeni sayaç aralığı yok.")
			} else if idle > total {
				detail = append(detail, "CPU sayaç aralığı tutarsız; ölçüm atlandı.")
			} else {
				percent := float64(total-idle) * 100 / float64(total)
				status.CPUPercent = &percent
			}
		}
		sampler.previous, sampler.hasPrevious = current, true
		detail = append(detail, "CPU: steal dahil; idle ve iowait hariç.")
	}
	if data, err := sampler.readFile("/proc/meminfo"); err != nil {
		detail = append(detail, "Bellek sayaçları okunamadı.")
	} else {
		total, used, err := parseResourceMemory(string(data))
		status.MemoryTotalBytes, status.MemoryUsedBytes = total, used
		if err != nil {
			detail = append(detail, "Bellek: "+err.Error())
		}
	}
	status.ConntrackCount = sampler.readOptionalCounter("/proc/sys/net/netfilter/nf_conntrack_count")
	status.ConntrackMax = sampler.readOptionalCounter("/proc/sys/net/netfilter/nf_conntrack_max")
	if status.ConntrackCount == nil || status.ConntrackMax == nil {
		detail = append(detail, "Conntrack kapasite sayaçlarının bir kısmı kullanılamıyor.")
	}
	status.Available = status.CPUPercent != nil || status.MemoryTotalBytes != nil || status.ConntrackCount != nil || status.ConntrackMax != nil
	status.Detail = strings.Join(detail, " ")
	sampler.lastSample, sampler.lastStatus = now, cloneResourceStatus(status)
	return status
}

func (sampler *ResourceSampler) readOptionalCounter(path string) *uint64 {
	data, err := sampler.readFile(path)
	if err != nil {
		return nil
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return nil
	}
	return &value
}

func readResourceFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if path == "/proc/stat" {
		// Only the first aggregate CPU line is needed. Reading every per-core
		// line would make host monitoring fail unnecessarily on large machines.
		line, err := bufio.NewReader(io.LimitReader(file, 4097)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(line) > 4096 {
			return nil, errors.New("aggregate CPU line exceeds measurement limit")
		}
		return []byte(line), nil
	}
	const maximum = 64 << 10
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximum {
		return nil, errors.New("resource file exceeds measurement limit")
	}
	return data, nil
}

func parseResourceCPU(text string) (cpuResourceCounters, error) {
	var fields []string
	for _, line := range strings.Split(text, "\n") {
		candidate := strings.Fields(line)
		if len(candidate) > 0 && candidate[0] == "cpu" {
			fields = candidate
			break
		}
	}
	if len(fields) < 5 {
		return cpuResourceCounters{}, errors.New("aggregate cpu line with at least four counters required")
	}
	var result cpuResourceCounters
	// user/nice already include guest/guest_nice. Adding columns 9/10 would
	// count those times twice, so only the first eight counters contribute.
	for i := 1; i < len(fields) && i <= 8; i++ {
		value, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			return cpuResourceCounters{}, errors.New("nonnegative integer CPU counters required")
		}
		if math.MaxUint64-result.total < value {
			return cpuResourceCounters{}, errors.New("CPU counter sum overflow")
		}
		result.total += value
		if i == 4 || i == 5 {
			if math.MaxUint64-result.idle < value {
				return cpuResourceCounters{}, errors.New("CPU idle counter sum overflow")
			}
			result.idle += value
		}
	}
	return result, nil
}

func parseResourceMemory(text string) (total, used *uint64, parseErr error) {
	values := map[string]uint64{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "MemTotal:" && fields[0] != "MemAvailable:" {
			continue
		}
		if len(fields) != 3 || fields[2] != "kB" {
			return nil, nil, errors.New("MemTotal/MemAvailable values must use kB")
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || value > math.MaxUint64/1024 {
			return nil, nil, errors.New("invalid or overflowing memory value")
		}
		if _, duplicate := values[fields[0]]; duplicate {
			return nil, nil, fmt.Errorf("duplicate %s counter", fields[0])
		}
		values[fields[0]] = value * 1024
	}
	totalBytes, ok := values["MemTotal:"]
	if !ok || totalBytes == 0 {
		return nil, nil, errors.New("positive MemTotal unavailable")
	}
	total = &totalBytes
	available, ok := values["MemAvailable:"]
	if !ok {
		return total, nil, errors.New("MemAvailable yok; kullanılan bellek tahmin edilmedi")
	}
	if available > totalBytes {
		return total, nil, errors.New("MemAvailable exceeds MemTotal")
	}
	usedBytes := totalBytes - available
	return total, &usedBytes, nil
}

func cloneResourceStatus(value ResourceStatus) ResourceStatus {
	value.CPUPercent = resourcePointerCopy(value.CPUPercent)
	value.MemoryUsedBytes = resourcePointerCopy(value.MemoryUsedBytes)
	value.MemoryTotalBytes = resourcePointerCopy(value.MemoryTotalBytes)
	value.ConntrackCount = resourcePointerCopy(value.ConntrackCount)
	value.ConntrackMax = resourcePointerCopy(value.ConntrackMax)
	return value
}

func resourcePointerCopy[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
