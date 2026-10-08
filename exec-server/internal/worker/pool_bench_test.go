package worker

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// fixtureOKExitPath is the path to the compiled ok_exit
// fixture binary, shared across all benchmarks in this file.
// Built once via TestMain.
var fixtureOKExitPath string

func TestMain(m *testing.M) {
	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(
		filepath.Dir(thisFile),
		"testdata", "fixtures", "ok_exit")

	tmp, err := os.CreateTemp("", "bench-okexit-*")
	if err != nil {
		panic(err)
	}
	_ = tmp.Close()
	fixtureOKExitPath = tmp.Name()
	defer func() { _ = os.Remove(fixtureOKExitPath) }()

	build := exec.Command("go", "build",
		"-o", fixtureOKExitPath, ".")
	build.Dir = fixtureDir
	if out, err := build.CombinedOutput(); err != nil {
		panic(string(out))
	}

	os.Exit(m.Run())
}

// BenchmarkWorkerPoolExecute runs Pool.Execute against the
// ok_exit fixture across a matrix of input sizes and worker
// counts. Measures total execute latency including fork/exec
// + stdin write + wait + classification.
func BenchmarkWorkerPoolExecute(b *testing.B) {
	inputSizes := []struct {
		name string
		size int
	}{
		{"in_0", 0},
		{"in_1K", 1024},
		{"in_64K", 64 * 1024},
		{"in_1M", 1024 * 1024},
	}
	workerCounts := []int{1, 4, 16}

	for _, sz := range inputSizes {
		for _, w := range workerCounts {
			name := sz.name + "/workers_" + itoa(w)
			b.Run(name, func(b *testing.B) {
				benchmarkPoolExecute(b, sz.size, w)
			})
		}
	}
}

func benchmarkPoolExecute(
	b *testing.B,
	inputSize int,
	workers int,
) {
	pool, err := NewPool(Config{
		TargetPath: fixtureOKExitPath,
		Workers:    workers,
	})
	if err != nil {
		b.Fatalf("NewPool: %v", err)
	}
	defer func() { _ = pool.Close() }()

	input := make([]byte, inputSize)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := pool.Execute(ctx, input)
			if err != nil {
				b.Errorf("Execute: %v", err)
				return
			}
			if result.Status !=
				ipcv1.ExecStatus_EXEC_STATUS_OK {
				b.Errorf("status = %v", result.Status)
				return
			}
		}
	})
}

// BenchmarkForkExecBaseline measures pure fork+exec cost for
// the ok_exit fixture, bypassing Pool. Sets the floor for
// what Pool.Execute could theoretically reach; the delta
// between this and BenchmarkWorkerPoolExecute is Pool
// coordination overhead.
func BenchmarkForkExecBaseline(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.CommandContext(ctx, fixtureOKExitPath)
		if err := cmd.Run(); err != nil {
			b.Fatalf("fork/exec: %v", err)
		}
	}
}

// itoa is a minimal int-to-string for the small set of values
// used by the worker-count matrix. Avoids an strconv import
// in this single-use site.
func itoa(n int) string {
	switch n {
	case 1:
		return "1"
	case 4:
		return "4"
	case 16:
		return "16"
	}
	return "?"
}
