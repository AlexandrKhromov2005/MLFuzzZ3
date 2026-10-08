// Copyright MLFuzzZ3 contributors.

package ipcv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// Smoke-tests verifying generated bindings round-trip through
// protobuf serialization. Four messages are covered, one per
// proto feature we rely on:
//   - InitRequest      : primitive fields (uint32, uint64)
//   - RunRequest       : bytes field
//   - RunResponse      : enum + optional message field
//   - Envelope         : oneof dispatch
//
// Protocol-level semantics (wire framing, fd passing, session
// lifecycle) are out of scope — tested at integration level
// in later Phase 1 tasks.

func TestInitRequestRoundTrip(t *testing.T) {
	orig := &InitRequest{
		ProtocolVersionMajor: 1,
		ProtocolVersionMinor: 0,
		RunTimeoutMs:         500,
	}
	data, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &InitRequest{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ProtocolVersionMajor != 1 ||
		got.ProtocolVersionMinor != 0 ||
		got.RunTimeoutMs != 500 {
		t.Errorf("mismatch after round-trip: %+v", got)
	}
}

func TestRunRequestBytes(t *testing.T) {
	orig := &RunRequest{
		Input: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	data, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &RunRequest{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Input) != 4 ||
		got.Input[0] != 0xde ||
		got.Input[3] != 0xef {
		t.Errorf("input bytes corrupted: %x", got.Input)
	}
}

func TestRunResponseEnumAndOptional(t *testing.T) {
	orig := &RunResponse{
		RunId:        42,
		Status:       ExecStatus_EXEC_STATUS_CRASH,
		ErrorMessage: "SIGSEGV at 0x0",
		EdgeResult:   &EdgeRunResult{},
	}
	data, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &RunResponse{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.RunId != 42 ||
		got.Status != ExecStatus_EXEC_STATUS_CRASH ||
		got.ErrorMessage != "SIGSEGV at 0x0" ||
		got.EdgeResult == nil {
		t.Errorf("mismatch after round-trip: %+v", got)
	}
}

func TestEnvelopeOneof(t *testing.T) {
	orig := &Envelope{
		Payload: &Envelope_RunRequest{
			RunRequest: &RunRequest{
				Input: []byte("hello"),
			},
		},
	}
	data, err := proto.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := &Envelope{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rr, ok := got.Payload.(*Envelope_RunRequest)
	if !ok {
		t.Fatalf("wrong oneof variant: %T", got.Payload)
	}
	if string(rr.RunRequest.Input) != "hello" {
		t.Errorf("input bytes corrupted: %q", rr.RunRequest.Input)
	}
}

// Invariant: numeric values of ExecStatus are part of the wire
// protocol. Reordering or renumbering silently breaks compatibility
// with all deployed readers. Lock the values explicitly.
func TestExecStatusValues(t *testing.T) {
	cases := []struct {
		name string
		got  int32
		want int32
	}{
		{"UNSPECIFIED", int32(ExecStatus_EXEC_STATUS_UNSPECIFIED), 0},
		{"OK", int32(ExecStatus_EXEC_STATUS_OK), 1},
		{"CRASH", int32(ExecStatus_EXEC_STATUS_CRASH), 2},
		{"HANG", int32(ExecStatus_EXEC_STATUS_HANG), 3},
		{"IPC_ERROR", int32(ExecStatus_EXEC_STATUS_IPC_ERROR), 4},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}
}
