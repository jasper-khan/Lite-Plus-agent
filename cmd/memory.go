package cmd

import (
	"log"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/v4/mem"
)

const (
	hostMemoryReserve = 128 << 20
	minMemory1CPU     = 64 << 20
	minMemoryMultiCPU = 96 << 20
	maxMemory1CPU     = 256 << 20
	maxMemoryMultiCPU = 512 << 20
	unlimitedCgroup   = int64(math.MaxInt64 / 2)
)

var (
	memoryBudget  = detectMemoryBudget
	effectiveCPUs = detectEffectiveCPUs
)

func configureRuntimeMemory() {
	cpus := effectiveCPUs()
	if os.Getenv("GOMAXPROCS") == "" && cpus > 0 {
		cur := runtime.GOMAXPROCS(0)
		if cpus < cur {
			runtime.GOMAXPROCS(cpus)
		}
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		total, limited := memoryBudget()
		limit := pickAgentMemoryLimit(total, cpus, limited)
		debug.SetMemoryLimit(limit)
		kind := "host"
		if limited {
			kind = "cgroup"
		}
		log.Printf("runtime memory limit %dMiB (%s %dMiB, %d cpu)", limit>>20, kind, total>>20, cpus)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
}

func pickAgentMemoryLimit(total int64, cpus int, limited bool) int64 {
	if cpus < 1 {
		cpus = 1
	}
	minLimit, maxLimit := int64(minMemoryMultiCPU), int64(maxMemoryMultiCPU)
	ratio := 0.50
	if cpus == 1 {
		minLimit, maxLimit = minMemory1CPU, maxMemory1CPU
		ratio = 0.40
	}
	if total <= 0 {
		return minLimit
	}
	budget := total
	if limited {
		if cpus == 1 {
			ratio = 0.70
		} else {
			ratio = 0.80
		}
	} else if total > hostMemoryReserve {
		budget = total - hostMemoryReserve
	} else {
		budget = total / 2
	}
	limit := int64(float64(budget) * ratio)
	if limit < minLimit {
		limit = minLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	capAt := total * 9 / 10
	if capAt > 0 && limit > capAt {
		limit = capAt
	}
	return limit
}

func detectMemoryBudget() (total int64, limited bool) {
	if n, ok := readCgroupMemory(); ok {
		return n, true
	}
	v, err := mem.VirtualMemory()
	if err != nil || v == nil || v.Total == 0 {
		return 0, false
	}
	return int64(v.Total), false
}

func detectEffectiveCPUs() int {
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	if c, ok := readCgroupCPUCount(); ok && c < n {
		n = c
	}
	if n < 1 {
		return 1
	}
	return n
}

func readCgroupMemory() (int64, bool) {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if n, ok := parseCgroupBytes(string(raw)); ok {
			return n, true
		}
	}
	return 0, false
}

func parseCgroupBytes(raw string) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.EqualFold(s, "max") {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= unlimitedCgroup {
		return 0, false
	}
	return n, true
}

func readCgroupCPUCount() (int, bool) {
	best := 0
	ok := false
	if raw, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		if n, parsed := parseCPUMax(string(raw)); parsed {
			best = n
			ok = true
		}
	}
	if raw, err := os.ReadFile("/sys/fs/cgroup/cpuset.cpus.effective"); err == nil {
		if n, parsed := parseCPUSet(string(raw)); parsed && (!ok || n < best) {
			best = n
			ok = true
		}
	} else if raw, err := os.ReadFile("/sys/fs/cgroup/cpuset.cpus"); err == nil {
		if n, parsed := parseCPUSet(string(raw)); parsed && (!ok || n < best) {
			best = n
			ok = true
		}
	}
	if !ok || best < 1 {
		return 0, false
	}
	return best, true
}

func parseCPUMax(raw string) (int, bool) {
	fields := strings.Fields(raw)
	if len(fields) == 0 || strings.EqualFold(fields[0], "max") {
		return 0, false
	}
	quota, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || quota <= 0 {
		return 0, false
	}
	period := int64(100000)
	if len(fields) > 1 {
		p, err := strconv.ParseInt(fields[1], 10, 64)
		if err == nil && p > 0 {
			period = p
		}
	}
	n := int((quota + period - 1) / period)
	if n < 1 {
		n = 1
	}
	return n, true
}

func parseCPUSet(raw string) (int, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || b < a {
				return 0, false
			}
			n += b - a + 1
			continue
		}
		if _, err := strconv.Atoi(part); err != nil {
			return 0, false
		}
		n++
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}
