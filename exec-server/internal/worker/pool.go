package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"mlfuzzz3/exec-server/internal/coverage"
	ipcv1 "mlfuzzz3/exec-server/internal/proto"
)

// CoverageConfig configures LD_PRELOAD-based coverage
// instrumentation per ADR 0017 + 0018 + 0019 + 0021. nil
// Config.Coverage disables coverage; pool runs target
// unmodified.
type CoverageConfig struct {
	// LibraryPath is the absolute path to libmlfuzzz3_cov.so.
	// Validated by coverage.NewChannelSet at construction.
	LibraryPath string
	// Channels is the set of memfd-backed coverage channels.
	// Pool acquires/releases channels per Run. Borrowed —
	// pool does not close. Lifecycle owned by
	// coverage.ChannelSet in main.go (ADR 0019 Task 8c).
	Channels *coverage.ChannelSet
	// Bucketizer, if non-nil, classifies each post-Run raw
	// bitmap into AFL-classic log2 buckets and tracks the
	// process-global seen-map; Result.Coverage.NewEdges
	// reports the per-Run delta. nil leaves NewEdges = 0
	// and skips the transform (backwards compatible with
	// pre-Task-8d coverage paths). Per ADR 0021 Task 8d.
	Bucketizer *coverage.Bucketizer
}

// Config controls Pool behavior. Per ADR 0011, this baseline
// forks a target process for each Execute call.
type Config struct {
	// TargetPath is the absolute path to the target binary.
	// Required.
	TargetPath string

	// TargetArgs are passed to the target on each invocation.
	TargetArgs []string

	// Workers is the number of concurrent worker goroutines.
	// Default: 1. Each worker processes one Execute call at
	// a time.
	Workers int

	// RunTimeout is the per-run hard limit. If the target does
	// not return within this duration, the process is killed
	// and Execute returns a hang-style error. Default: 5
	// seconds.
	RunTimeout time.Duration

	// Coverage, if non-nil, enables LD_PRELOAD coverage
	// instrumentation: target is spawned with LD_PRELOAD set
	// to LibraryPath and MLFUZZZ3_COV_FD=3 (fd 3 = first
	// ExtraFile). nil disables; pool unchanged.
	Coverage *CoverageConfig
}

// CoverageResult carries per-Run coverage observations.
// Populated by Pool when Config.Coverage != nil; nil
// otherwise (ADR 0019 Task 8c).
type CoverageResult struct {
	// ChannelIndex is the 0-indexed position in the
	// ChannelSet of the channel used for this Run. Maps
	// directly to EdgeRunResult.channel_index in the
	// protocol.
	ChannelIndex int

	// Hits is the count of non-zero bytes in the raw bitmap
	// after Run completion (pre-bucketization signal kept
	// for debugging / correlation).
	Hits int

	// NewEdges is the count of bucketized edge bits newly
	// observed in this Run relative to the global seen-map
	// (process lifetime). 0 when CoverageConfig.Bucketizer
	// is nil or no new buckets were introduced. Per ADR
	// 0021 Task 8d.
	NewEdges uint32
}

// BranchResult carries the per-Run summary of the branch-value
// channel (ADR 0033). Populated by Pool alongside Coverage when the
// branch segment was read; nil otherwise. The records themselves stay
// in the SHM segment and are read out-of-band by the core.
type BranchResult struct {
	// RecordCount is the number of comparison records the runtime
	// appended this Run (the segment header count).
	RecordCount uint32

	// Overflow is true if the runtime dropped records because the
	// segment filled up. The log is then incomplete.
	Overflow bool
}

// Result carries the outcome of one target execution.
type Result struct {
	// Status is the classified execution outcome.
	Status ipcv1.ExecStatus

	// Signal is the signal that terminated the target, if
	// Status == CRASH. Zero otherwise.
	Signal syscall.Signal

	// ExitCode is the target's exit code if it exited
	// normally. Undefined if Status != OK.
	ExitCode int

	// Duration is wall-clock time from Execute entry to
	// target termination.
	Duration time.Duration

	// ErrorMessage is populated for Status == IPC_ERROR paths
	// (spawn failures, unexpected wait errors).
	ErrorMessage string

	// Coverage, if non-nil, carries per-Run coverage
	// observations. Set by Pool when Config.Coverage != nil
	// and the Run reached classification stage.
	Coverage *CoverageResult

	// Branch, if non-nil, carries the per-Run branch-value channel
	// summary (ADR 0033). Set alongside Coverage when the branch
	// segment was read successfully.
	Branch *BranchResult
}

// job is an internal unit of work passed from Execute to
// worker goroutines.
type job struct {
	ctx      context.Context
	input    []byte
	resultCh chan<- jobResult
}

// jobResult is what the worker sends back to Execute.
type jobResult struct {
	result *Result
	err    error
}

// Pool manages a fixed set of worker goroutines that execute
// target processes. Concurrent calls to Execute are serialized
// through an internal jobs channel; the degree of parallelism
// is Config.Workers.
type Pool struct {
	cfg     Config
	jobs    chan job
	wg      sync.WaitGroup
	closeMu sync.Mutex
	closed  bool
}

// Errors returned by Pool operations.
var (
	ErrPoolClosed      = errors.New("worker: pool is closed")
	ErrEmptyTargetPath = errors.New(
		"worker: Config.TargetPath is required")
)

// NewPool constructs and starts a Pool. Workers begin accepting
// jobs immediately. Call Close to stop them.
func NewPool(cfg Config) (*Pool, error) {
	if cfg.TargetPath == "" {
		return nil, ErrEmptyTargetPath
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	if cfg.RunTimeout <= 0 {
		cfg.RunTimeout = 5 * time.Second
	}

	p := &Pool{
		cfg:  cfg,
		jobs: make(chan job),
	}

	for i := 0; i < cfg.Workers; i++ {
		p.wg.Add(1)
		go p.workerLoop()
	}

	return p, nil
}

// Execute submits input for execution and blocks until the
// target terminates or the context is cancelled. Safe for
// concurrent use.
func (p *Pool) Execute(
	ctx context.Context,
	input []byte,
) (*Result, error) {
	if p.isClosed() {
		return nil, ErrPoolClosed
	}

	resultCh := make(chan jobResult, 1)
	j := job{
		ctx:      ctx,
		input:    input,
		resultCh: resultCh,
	}

	select {
	case p.jobs <- j:
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"worker: context cancelled before job dispatch: %w",
			ctx.Err())
	}

	select {
	case r := <-resultCh:
		return r.result, r.err
	case <-ctx.Done():
		return nil, fmt.Errorf(
			"worker: context cancelled while awaiting result: %w",
			ctx.Err())
	}
}

// Close signals all workers to stop after they finish their
// current jobs. Blocks until all workers exit. Subsequent
// Execute calls return ErrPoolClosed.
func (p *Pool) Close() error {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return nil
	}
	p.closed = true
	close(p.jobs)
	p.closeMu.Unlock()

	p.wg.Wait()
	return nil
}

func (p *Pool) isClosed() bool {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	return p.closed
}

// workerLoop is the goroutine that pulls jobs off the channel
// and executes them.
func (p *Pool) workerLoop() {
	defer p.wg.Done()

	for j := range p.jobs {
		result, err := p.runOnce(j.ctx, j.input)
		j.resultCh <- jobResult{result: result, err: err}
	}
}

// runOnce forks+execs the target binary, feeds input on
// stdin, and classifies the termination outcome. When
// Config.Coverage != nil, runOnce acquires a coverage
// channel from the pool's ChannelSet, resets the bitmap
// before spawn, and reads the bitmap after exit; the
// channel is released back to the set on return (ADR 0019
// Task 8c).
func (p *Pool) runOnce(
	parentCtx context.Context,
	input []byte,
) (*Result, error) {
	var (
		ch    *coverage.Channel
		chIdx = -1
	)
	if p.cfg.Coverage != nil {
		acqCh, idx, err := p.cfg.Coverage.Channels.Acquire(parentCtx)
		if err != nil {
			return nil, fmt.Errorf(
				"worker: coverage acquire: %w", err)
		}
		ch = acqCh
		chIdx = idx
		defer p.cfg.Coverage.Channels.Release(ch)
		if rerr := ch.Reset(); rerr != nil {
			return nil, fmt.Errorf(
				"worker: coverage reset: %w", rerr)
		}
		// Branch-value channel (ADR 0033): independent segment, reset
		// before each spawn just like the edge bitmap.
		if rerr := ch.ResetBranch(); rerr != nil {
			return nil, fmt.Errorf(
				"worker: branch reset: %w", rerr)
		}
	}

	ctx, cancel := context.WithTimeout(
		parentCtx, p.cfg.RunTimeout)
	defer cancel()

	start := time.Now()

	cmd := exec.CommandContext(
		ctx, p.cfg.TargetPath, p.cfg.TargetArgs...)
	cmd.Stdin = bytes.NewReader(input)

	if ch != nil {
		// ExtraFiles[0] -> fd 3 (edge bitmap, MLFUZZZ3_COV_FD),
		// ExtraFiles[1] -> fd 4 (branch segment, MLFUZZZ3_BRANCH_FD).
		// Per ADR 0033 the branch channel is a second, independent
		// memfd; the edge channel (fd 3) is unchanged.
		cmd.ExtraFiles = []*os.File{ch.MemfdFile(), ch.BranchMemfdFile()}
		// os.Environ() pass-through; Go append-last-wins
		// semantics ensure explicit values take precedence
		// even if parent process inherits MLFUZZZ3_COV_FD
		// or LD_PRELOAD. Filtering not needed (ADR 0018).
		cmd.Env = append(os.Environ(),
			"LD_PRELOAD="+p.cfg.Coverage.LibraryPath,
			"MLFUZZZ3_COV_FD=3",
			"MLFUZZZ3_BRANCH_FD=4",
		)
	}

	runErr := cmd.Run()
	duration := time.Since(start)

	// Classify outcome.
	result := &Result{Duration: duration}

	if cmd.ProcessState == nil {
		// cmd.Run returned before spawning — this is IPC-side
		// failure (e.g. target binary missing).
		result.Status =
			ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR
		result.ErrorMessage = fmt.Sprintf(
			"worker: spawn failed: %v", runErr)
		return result, nil
	}

	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		// Non-Unix platform or unexpected state.
		result.Status =
			ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR
		result.ErrorMessage =
			"worker: WaitStatus not available"
		return result, nil
	}

	switch {
	case ws.Exited():
		result.ExitCode = ws.ExitStatus()
		if result.ExitCode == 0 {
			result.Status = ipcv1.ExecStatus_EXEC_STATUS_OK
		} else {
			// Non-zero exit is treated as OK for baseline —
			// targets signal crashes via signal termination.
			// Non-zero exit is "normal program error".
			result.Status = ipcv1.ExecStatus_EXEC_STATUS_OK
		}

	case ws.Signaled():
		sig := ws.Signal()
		result.Signal = sig
		if isCrashSignal(sig) {
			result.Status =
				ipcv1.ExecStatus_EXEC_STATUS_CRASH
		} else if errors.Is(ctx.Err(),
			context.DeadlineExceeded) {
			result.Status =
				ipcv1.ExecStatus_EXEC_STATUS_HANG
		} else {
			result.Status =
				ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR
			result.ErrorMessage = fmt.Sprintf(
				"worker: unexpected signal %v", sig)
		}

	default:
		result.Status = ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR
		result.ErrorMessage = "worker: neither exited nor signaled"
	}

	if ch != nil {
		bm, rerr := ch.Read()
		if rerr == nil {
			hits := 0
			for _, b := range bm {
				if b != 0 {
					hits++
				}
			}
			var newEdges uint32
			if p.cfg.Coverage.Bucketizer != nil {
				// Reuse bm as the bucketized buffer; ADR
				// 0021 §Решение — Classify supports
				// aliasing, ch.Read returns a fresh copy
				// so bm is exclusively owned here.
				if cerr := p.cfg.Coverage.Bucketizer.
					Classify(bm, bm); cerr == nil {
					if n, uerr := p.cfg.Coverage.
						Bucketizer.UpdateSeen(bm); uerr == nil {
						newEdges = n
					}
				}
			}
			result.Coverage = &CoverageResult{
				ChannelIndex: chIdx,
				Hits:         hits,
				NewEdges:     newEdges,
			}
		}
		// Read failure does not fail the Run — preserves
		// Task 8b semantic (coverage is best-effort).
		// Caller observes nil Coverage and may log.

		// Branch-value summary (ADR 0033): best-effort like edge.
		// The records stay in the SHM segment for the core to read
		// out-of-band; here we only surface count + overflow.
		if count, overflow, berr := ch.ReadBranchSummary(); berr == nil {
			result.Branch = &BranchResult{
				RecordCount: count,
				Overflow:    overflow,
			}
		}
	}

	return result, nil
}

// isCrashSignal returns true for signals that indicate a
// genuine target crash (as opposed to an external kill or
// hang-induced kill).
func isCrashSignal(sig syscall.Signal) bool {
	switch sig {
	case syscall.SIGSEGV,
		syscall.SIGABRT,
		syscall.SIGBUS,
		syscall.SIGILL,
		syscall.SIGFPE:
		return true
	default:
		return false
	}
}
