// Binary exec-server is the Go-side half of the fuzzer: it owns
// the target process pool and reports coverage to the C++ Core
// over IPC. Per ADR 0012, exec-server is an internal subprocess
// of the fuzzer core — it is not launched by users directly. The
// IPC socket is inherited as fd 3 via ExtraFiles during
// fork+exec; there is no -socket flag because no filesystem
// socket path is involved.
//
// See docs/ARCHITECTURE.md §4.10 and docs/DECISIONS/0012-*.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mlfuzzz3/exec-server/internal/common/config"
	"mlfuzzz3/exec-server/internal/common/logging"
	"mlfuzzz3/exec-server/internal/coverage"
	"mlfuzzz3/exec-server/internal/crashrec"
	"mlfuzzz3/exec-server/internal/ipc"
	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/watchdog"
	"mlfuzzz3/exec-server/internal/worker"
)

// version is overwritten at release time in a later phase.
const version = "0.0.0"

// ipcSocketFd is the inherited fd assigned to the IPC socket
// by the parent fuzzer core (first ExtraFile per os/exec).
const ipcSocketFd = 3

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable body of main.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exec-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "",
		"path to YAML configuration file (log section only)")
	showVersion := fs.Bool("version", false,
		"print version and exit")
	targetPath := fs.String("target", "",
		"path to target binary (required)")
	workers := fs.Int("workers", 1,
		"number of worker goroutines")
	runTimeoutMs := fs.Int("run-timeout-ms", 5000,
		"per-run timeout in milliseconds")
	crashesDir := fs.String("crashes-dir", "",
		"directory for crash/hang artifacts "+
			"(empty = disabled)")
	recordStatus := fs.String("record-status", "crash,hang",
		"comma-separated statuses to record: "+
			"crash,hang,ipc_error")
	covLibrary := fs.String("cov-library", "",
		"absolute path to libmlfuzzz3_cov.so "+
			"(coverage disabled if empty)")
	targetArgs := fs.String("target-args", "",
		"whitespace-separated args passed to the target on "+
			"every run (input stays on stdin); empty = none "+
			"(ADR 0040)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "exec-server v%s\n", version)
		return 0
	}

	// Load config (log section only per ADR 0012).
	cfg := config.Defaults()
	if *cfgPath != "" {
		loaded, err := config.LoadFromFile(*cfgPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "fatal: %v\n", err)
			return 2
		}
		cfg = loaded
	}

	if _, err := logging.Init(cfg.Log); err != nil {
		_, _ = fmt.Fprintf(stderr, "fatal: %v\n", err)
		return 2
	}

	// Parse -record-status.
	statuses, err := parseRecordStatus(*recordStatus)
	if err != nil {
		_, _ = fmt.Fprintf(stderr,
			"fatal: -record-status: %v\n", err)
		return 2
	}

	// Validate required flags.
	if *targetPath == "" {
		_, _ = fmt.Fprintf(stderr,
			"fatal: -target is required\n")
		return 2
	}
	if *workers < 1 {
		_, _ = fmt.Fprintf(stderr,
			"fatal: -workers must be >= 1\n")
		return 2
	}
	if *runTimeoutMs < 1 {
		_, _ = fmt.Fprintf(stderr,
			"fatal: -run-timeout-ms must be >= 1\n")
		return 2
	}

	// Coverage validation (ADR 0018 + 0019). Empty
	// -cov-library disables coverage; pool runs unchanged.
	// Multi-worker supported via ChannelSet (ADR 0019 Task
	// 8c) — N channels, one per worker, acquired/released
	// inside pool.runOnce.
	var covCS *coverage.ChannelSet
	if *covLibrary != "" {
		if !filepath.IsAbs(*covLibrary) {
			_, _ = fmt.Fprintf(stderr,
				"fatal: -cov-library must be absolute "+
					"path: %q\n", *covLibrary)
			return 2
		}
		cs, err := coverage.NewChannelSet(
			*covLibrary, *workers)
		if err != nil {
			_, _ = fmt.Fprintf(stderr,
				"fatal: coverage init: %v\n", err)
			return 2
		}
		covCS = cs
		defer func() { _ = covCS.Close() }()
	}

	// Acquire IPC socket from inherited fd.
	ipcFile := os.NewFile(ipcSocketFd, "ipc")
	if ipcFile == nil {
		_, _ = fmt.Fprintf(stderr,
			"fatal: exec-server is an internal subprocess, "+
				"must be spawned by fuzzer core with IPC "+
				"socket at fd %d\n", ipcSocketFd)
		return 2
	}
	fileConn, err := net.FileConn(ipcFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr,
			"fatal: invalid IPC socket at fd %d: %v\n",
			ipcSocketFd, err)
		// ipcFile was duplicated by net.FileConn on success,
		// but on failure we should close.
		_ = ipcFile.Close()
		return 2
	}
	// net.FileConn duplicates the fd internally. The original
	// ipcFile can be closed.
	_ = ipcFile.Close()

	slog.Info("exec-server started",
		"version", version,
		"target", *targetPath,
		"workers", *workers,
		"run_timeout_ms", *runTimeoutMs,
		"log_level", cfg.Log.Level,
		"log_format", cfg.Log.Format,
	)

	// Create worker pool.
	poolCfg := worker.Config{
		TargetPath: *targetPath,
		// strings.Fields on an empty/whitespace value yields a nil
		// slice, leaving the target argv unchanged (ADR 0040).
		TargetArgs: strings.Fields(*targetArgs),
		Workers:    *workers,
		RunTimeout: time.Duration(*runTimeoutMs) *
			time.Millisecond,
	}
	// Bucketizer (ADR 0021 Task 8d) owns the process-global
	// seen-map and the AFL-classic log2 bucket LUT. Single
	// instance shared across all workers; no external
	// resources so no Close required.
	if covCS != nil {
		poolCfg.Coverage = &worker.CoverageConfig{
			LibraryPath: *covLibrary,
			Channels:    covCS,
			Bucketizer:  coverage.NewBucketizer(),
		}
	}
	pool, err := worker.NewPool(poolCfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr,
			"fatal: create worker pool: %v\n", err)
		_ = fileConn.Close()
		return 2
	}

	// Set up context with signal-driven cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ipcConn := ipc.NewConn(fileConn)

	// Create watchdog observer.
	wdog := watchdog.New(slog.Default())

	// Create crash recorder.
	recorder, err := crashrec.New(crashrec.Config{
		Dir:      *crashesDir,
		Statuses: statuses,
		Logger:   slog.Default(),
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr,
			"fatal: create crash recorder: %v\n", err)
		_ = fileConn.Close()
		_ = pool.Close()
		return 2
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			slog.Info("signal received, shutting down",
				"signal", sig.String())
			cancel()
			// Close the connection to unblock any pending
			// ReadEnvelope in Serve.
			_ = ipcConn.Close()
		case <-ctx.Done():
			// run returning normally — stop listening for
			// signals.
		}
		signal.Stop(sigCh)
	}()

	// Build handler that bridges IPC to worker.Pool.
	handler := func(
		hctx context.Context,
		req *ipcv1.RunRequest,
	) (*ipcv1.RunResponse, error) {
		result, err := pool.Execute(hctx, req.Input)
		if err != nil {
			return nil, err
		}
		if result.Coverage != nil {
			slog.Debug("coverage edges",
				"hits", result.Coverage.Hits,
				"new", result.Coverage.NewEdges,
				"channel", result.Coverage.ChannelIndex)
		}
		wdog.Record(result)
		recorder.Record(req.Input, result)
		resp := &ipcv1.RunResponse{
			Status:       result.Status,
			ErrorMessage: result.ErrorMessage,
			// RunId is assigned by ipc.Serve.
		}
		if result.Coverage != nil {
			// Per ADR 0019: EdgeRunResult.channel_index
			// identifies which announced memfd the peer
			// should read for this Run. Bitmap content
			// itself is delivered out-of-band per ADR
			// 0017 §Q10. NewEdges added in ADR 0021 Task
			// 8d — scalar count of bucketized bits newly
			// observed relative to the process-global
			// seen-map.
			resp.EdgeResult = &ipcv1.EdgeRunResult{
				ChannelIndex: int32(
					result.Coverage.ChannelIndex),
				NewEdges: result.Coverage.NewEdges,
			}
		}
		if result.Branch != nil {
			// Per-run branch-value channel summary (ADR 0033).
			// record_count tells the core how many comparison
			// records to read from the announced branch memfd;
			// overflow marks the log as truncated.
			resp.BranchResult = &ipcv1.BranchRunResult{
				RecordCount: result.Branch.RecordCount,
				Overflow:    result.Branch.Overflow,
			}
		}
		return resp, nil
	}

	// Build ServerConfig.Channels: announce all coverage
	// memfds via SCM_RIGHTS at handshake when -cov-library
	// is set. Multi-channel layout per ADR 0019 Task 8c —
	// peer correlates per-Run results by EdgeRunResult.
	// channel_index, indexing into this announcement list.
	var channels []ipc.ChannelWithFD
	if covCS != nil {
		chs := covCS.Channels()
		// Edge announcements first, then branch (ADR 0033). The order
		// matters: EdgeRunResult.channel_index is the position in this
		// list, so keeping all edge channels at indices [0, N) leaves
		// that contract unchanged; branch channels occupy [N, 2N).
		for i := range chs {
			channels = append(channels, ipc.ChannelWithFD{
				Announcement: chs[i].Announcement(),
				FD:           chs[i].FD(),
			})
		}
		for i := range chs {
			channels = append(channels, ipc.ChannelWithFD{
				Announcement: chs[i].BranchAnnouncement(),
				FD:           chs[i].BranchFD(),
			})
		}
	}

	// Serve blocks until Shutdown, client disconnect, or error.
	serveErr := ipc.Serve(ctx, ipcConn, ipc.ServerConfig{
		Channels: channels,
	}, handler)

	// Graceful pool shutdown (waits for in-flight runs).
	_ = pool.Close()

	wdog.LogSummary()

	switch {
	case serveErr == nil:
		// Clean Shutdown via ShutdownRequest from client.
		slog.Info("exec-server stopped cleanly")
		return 0
	case errors.Is(serveErr, io.EOF):
		// Client disconnected without ShutdownRequest. Not
		// a clean shutdown, but not an error either — treat
		// as normal exit for baseline.
		slog.Info("client disconnected, shutting down")
		return 0
	default:
		slog.Error("serve loop terminated with error",
			"err", serveErr)
		_, _ = fmt.Fprintf(stderr,
			"fatal: serve: %v\n", serveErr)
		return 1
	}
}

// parseRecordStatus parses a comma-separated list of status
// names from -record-status into ExecStatus enum values.
func parseRecordStatus(
	s string,
) ([]ipcv1.ExecStatus, error) {
	if s == "" {
		return nil, nil
	}
	var out []ipcv1.ExecStatus
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(strings.ToLower(tok))
		switch tok {
		case "crash":
			out = append(out,
				ipcv1.ExecStatus_EXEC_STATUS_CRASH)
		case "hang":
			out = append(out,
				ipcv1.ExecStatus_EXEC_STATUS_HANG)
		case "ipc_error":
			out = append(out,
				ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR)
		default:
			return nil, fmt.Errorf(
				"unknown status %q (want "+
					"crash|hang|ipc_error)", tok)
		}
	}
	return out, nil
}
