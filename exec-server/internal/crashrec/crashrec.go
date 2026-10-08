package crashrec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ipcv1 "mlfuzzz3/exec-server/internal/proto"
	"mlfuzzz3/exec-server/internal/worker"
)

// Config controls Recorder behavior.
type Config struct {
	// Dir is the root directory for crash artifacts. Empty
	// string means recording is disabled — Record becomes
	// a no-op with zero overhead.
	Dir string

	// Statuses selects which worker.Result.Status values
	// trigger persistence. Outcomes not in this list are
	// silently ignored by Record. Empty list = disabled
	// equivalent.
	Statuses []ipcv1.ExecStatus

	// Logger receives warn on I/O errors, info on
	// successful records. If nil, slog.Default is used.
	Logger *slog.Logger
}

// Recorder persists (input, metadata) bundles for selected
// outcomes. Safe for concurrent use.
type Recorder struct {
	dir      string
	statuses map[ipcv1.ExecStatus]struct{}
	logger   *slog.Logger
}

// New constructs a Recorder. If cfg.Dir is empty, returns a
// valid no-op Recorder. Otherwise MkdirAll is called on
// cfg.Dir and its per-status subdirectories; a non-nil
// error indicates the Recorder is unusable.
func New(cfg Config) (*Recorder, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	r := &Recorder{
		dir:      cfg.Dir,
		logger:   logger,
		statuses: make(map[ipcv1.ExecStatus]struct{}),
	}
	for _, s := range cfg.Statuses {
		r.statuses[s] = struct{}{}
	}

	if cfg.Dir == "" {
		return r, nil
	}

	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, fmt.Errorf(
			"crashrec: create root dir: %w", err)
	}
	// Pre-create per-status subdirectories for recordable
	// statuses. Avoids per-Record MkdirAll overhead.
	for s := range r.statuses {
		sub := statusSubdir(s)
		if sub == "" {
			continue
		}
		path := filepath.Join(cfg.Dir, sub)
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, fmt.Errorf(
				"crashrec: create %s dir: %w", sub, err)
		}
	}

	return r, nil
}

// Record persists (input, metadata) for a single outcome.
// Implementation uses Mkdir-probe for collision detection
// because os.Rename on Linux does not fail-if-exists (it
// overwrites silently). Atomicity of name claim is
// preserved by Mkdir's OS-level fail-if-exists semantics;
// writes happen in the already-claimed directory. Partial
// writes (exec-server killed mid-write) leave an incomplete
// directory — Phase 1.5 adds startup cleanup.
//
// Errors are logged as warnings and swallowed. Record never
// blocks fuzzing progress.
func (r *Recorder) Record(
	input []byte,
	result *worker.Result,
) {
	if r.dir == "" || result == nil {
		return
	}
	if _, ok := r.statuses[result.Status]; !ok {
		return
	}
	sub := statusSubdir(result.Status)
	if sub == "" {
		// Unknown status — can't map to subdir. Skip.
		return
	}

	now := time.Now().UTC()
	nanos := now.UnixNano()

	sum := sha256.Sum256(input)
	fullHash := hex.EncodeToString(sum[:])
	shortHash := fullHash[:16]

	baseName := fmt.Sprintf("%d_%s", nanos, shortHash)
	parent := filepath.Join(r.dir, sub)

	// Mkdir-probe: try the canonical name, then a single
	// "_1" suffix on collision.
	finalPath, err := r.claimDir(parent, baseName)
	if err != nil {
		r.logger.Warn("crashrec: name collision",
			"base", baseName, "err", err)
		return
	}

	inputPath := filepath.Join(finalPath, "input.bin")
	if err := os.WriteFile(
		inputPath, input, 0o644); err != nil {
		r.logger.Warn("crashrec: write input",
			"path", inputPath, "err", err)
		return
	}

	meta := buildMeta(now, nanos, result, len(input), fullHash)
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		r.logger.Warn("crashrec: marshal meta",
			"path", finalPath, "err", err)
		return
	}
	metaPath := filepath.Join(finalPath, "meta.json")
	if err := os.WriteFile(
		metaPath, metaBytes, 0o644); err != nil {
		r.logger.Warn("crashrec: write meta",
			"path", metaPath, "err", err)
		return
	}

	r.logger.Info("crashrec: recorded",
		"status", result.Status.String(),
		"path", finalPath,
		"input_size", len(input))
}

// claimDir attempts to Mkdir baseName under parent, with a
// single "_1" retry on collision. Returns the created
// directory path on success.
func (r *Recorder) claimDir(
	parent, baseName string,
) (string, error) {
	for _, candidate := range []string{
		baseName, baseName + "_1",
	} {
		path := filepath.Join(parent, candidate)
		err := os.Mkdir(path, 0o755)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		// Collision; try next candidate.
	}
	return "", fmt.Errorf(
		"both %s and %s_1 already exist",
		baseName, baseName)
}

// statusSubdir maps an ExecStatus to the lowercase
// snake_case subdirectory under Config.Dir. Returns empty
// for statuses we do not record (OK, UNSPECIFIED, unknown
// future values).
func statusSubdir(s ipcv1.ExecStatus) string {
	switch s {
	case ipcv1.ExecStatus_EXEC_STATUS_CRASH:
		return "crashes"
	case ipcv1.ExecStatus_EXEC_STATUS_HANG:
		return "hangs"
	case ipcv1.ExecStatus_EXEC_STATUS_IPC_ERROR:
		return "ipc_errors"
	}
	return ""
}

// metaJSON is the persisted metadata schema. Field names
// match docs/DECISIONS/0014.
type metaJSON struct {
	TimestampNS  int64   `json:"timestamp_ns"`
	TimestampISO string  `json:"timestamp_iso"`
	Status       string  `json:"status"`
	TargetPath   string  `json:"target_path"`
	Signal       *string `json:"signal"`
	ExitCode     *int    `json:"exit_code"`
	DurationMs   int64   `json:"duration_ms"`
	InputSize    int     `json:"input_size"`
	InputSHA256  string  `json:"input_sha256"`
}

func buildMeta(
	t time.Time,
	nanos int64,
	result *worker.Result,
	inputSize int,
	inputSHA256 string,
) *metaJSON {
	statusStr := strings.ToLower(strings.TrimPrefix(
		result.Status.String(), "EXEC_STATUS_"))

	var sig *string
	if result.Status ==
		ipcv1.ExecStatus_EXEC_STATUS_CRASH {
		s := result.Signal.String()
		sig = &s
	}

	// ExitCode is reserved (null in baseline) — worker.Pool
	// treats non-zero exits as OK, signals as CRASH/HANG.
	var exitCode *int

	return &metaJSON{
		TimestampNS:  nanos,
		TimestampISO: t.Format(time.RFC3339Nano),
		Status:       statusStr,
		// TargetPath: worker.Result does not carry target
		// path; reserved for Phase 1.5 when Pool threads it
		// through.
		TargetPath:  "",
		Signal:      sig,
		ExitCode:    exitCode,
		DurationMs:  result.Duration.Milliseconds(),
		InputSize:   inputSize,
		InputSHA256: inputSHA256,
	}
}
