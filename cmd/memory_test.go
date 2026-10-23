package cmd

import (
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestPickAgentMemoryLimit(t *testing.T) {
	const mib = int64(1 << 20)
	cases := []struct {
		name     string
		total    int64
		cpus     int
		limited  bool
		wantMiB  int64
	}{
		{"unknown 1cpu", 0, 1, false, 64},
		{"unknown 2cpu", 0, 2, false, 96},
		{"256 host 1cpu", 256 * mib, 1, false, 64},
		{"256 host 2cpu", 256 * mib, 2, false, 96},
		{"512 host 1cpu", 512 * mib, 1, false, 153},
		{"512 host 2cpu", 512 * mib, 2, false, 192},
		{"1g host 1cpu", 1024 * mib, 1, false, 256},
		{"1g host 2cpu", 1024 * mib, 2, false, 448},
		{"2g host 1cpu", 2048 * mib, 1, false, 256},
		{"2g host 2cpu", 2048 * mib, 2, false, 512},
		{"256 cgroup 1cpu", 256 * mib, 1, true, 179},
		{"256 cgroup 2cpu", 256 * mib, 2, true, 204},
		{"512 cgroup 1cpu", 512 * mib, 1, true, 256},
		{"1g cgroup 2cpu", 1024 * mib, 2, true, 512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickAgentMemoryLimit(tc.total, tc.cpus, tc.limited)
			gotMiB := got >> 20
			if gotMiB != tc.wantMiB {
				t.Fatalf("limit %dMiB, want %dMiB", gotMiB, tc.wantMiB)
			}
		})
	}
}

func TestParseCPUMax(t *testing.T) {
	if n, ok := parseCPUMax("max 100000"); ok {
		t.Fatalf("unlimited parsed as %d", n)
	}
	n, ok := parseCPUMax("100000 100000")
	if !ok || n != 1 {
		t.Fatalf("1 cpu quota = %d %v", n, ok)
	}
	n, ok = parseCPUMax("200000 100000")
	if !ok || n != 2 {
		t.Fatalf("2 cpu quota = %d %v", n, ok)
	}
	n, ok = parseCPUMax("150000 100000")
	if !ok || n != 2 {
		t.Fatalf("1.5 cpu ceil = %d %v", n, ok)
	}
}

func TestParseCPUSet(t *testing.T) {
	n, ok := parseCPUSet("0")
	if !ok || n != 1 {
		t.Fatalf("single = %d %v", n, ok)
	}
	n, ok = parseCPUSet("0-1")
	if !ok || n != 2 {
		t.Fatalf("range = %d %v", n, ok)
	}
	n, ok = parseCPUSet("0-1,3")
	if !ok || n != 3 {
		t.Fatalf("list = %d %v", n, ok)
	}
}

func TestParseCgroupBytes(t *testing.T) {
	if _, ok := parseCgroupBytes("max"); ok {
		t.Fatal("max should be unlimited")
	}
	n, ok := parseCgroupBytes("268435456")
	if !ok || n != 256<<20 {
		t.Fatalf("256MiB = %d %v", n, ok)
	}
	if _, ok := parseCgroupBytes("9223372036854771712"); ok {
		t.Fatal("v1 unlimited sentinel")
	}
}

func TestConfigureRuntimeMemoryDefault(t *testing.T) {
	if err := os.Unsetenv("GOMEMLIMIT"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOGC"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("GOMAXPROCS"); err != nil {
		t.Fatal(err)
	}
	prevBudget, prevCPUs := memoryBudget, effectiveCPUs
	memoryBudget = func() (int64, bool) { return 512 << 20, false }
	effectiveCPUs = func() int { return 1 }
	t.Cleanup(func() {
		memoryBudget = prevBudget
		effectiveCPUs = prevCPUs
		_ = os.Unsetenv("GOMEMLIMIT")
		_ = os.Unsetenv("GOGC")
		_ = os.Unsetenv("GOMAXPROCS")
	})

	prevLimit := debug.SetMemoryLimit(math.MaxInt64)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	want := pickAgentMemoryLimit(512<<20, 1, false)
	gotLimit := debug.SetMemoryLimit(want)
	if gotLimit != want {
		t.Fatalf("memory limit = %d, want %d", gotLimit, want)
	}
	gotGC := debug.SetGCPercent(50)
	if gotGC != 50 {
		t.Fatalf("GOGC = %d, want 50", gotGC)
	}
}

func TestConfigureRuntimeMemoryRespectsEnv(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "256MiB")
	t.Setenv("GOGC", "200")
	t.Setenv("GOMAXPROCS", "4")

	const keepLimit int64 = 123 << 20
	prevLimit := debug.SetMemoryLimit(keepLimit)
	prevGC := debug.SetGCPercent(100)
	prevMax := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prevLimit)
		debug.SetGCPercent(prevGC)
		runtime.GOMAXPROCS(prevMax)
	})

	configureRuntimeMemory()

	gotLimit := debug.SetMemoryLimit(keepLimit)
	if gotLimit != keepLimit {
		t.Fatalf("GOMEMLIMIT env should skip override, got %d", gotLimit)
	}
	gotGC := debug.SetGCPercent(100)
	if gotGC != 100 {
		t.Fatalf("GOGC env should skip override, got %d", gotGC)
	}
	if runtime.GOMAXPROCS(0) != prevMax {
		t.Fatalf("GOMAXPROCS env should skip override, got %d want %d", runtime.GOMAXPROCS(0), prevMax)
	}
}
