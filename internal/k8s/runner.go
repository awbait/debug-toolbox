package k8s

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// CmdResult holds the output of an external command invocation.
type CmdResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner abstracts external CLI calls (kubectl, istioctl) for easy testing.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (CmdResult, error)
	RunWithStdin(ctx context.Context, stdin string, name string, args ...string) (CmdResult, error)
	History() []string
}

// ExecRunner executes real system binaries via os/exec without invoking a shell.
type ExecRunner struct {
	mu      sync.Mutex
	history []string
}

func NewExecRunner() *ExecRunner {
	return &ExecRunner{}
}

func (r *ExecRunner) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	return r.RunWithStdin(ctx, "", name, args...)
}

func (r *ExecRunner) RunWithStdin(ctx context.Context, stdin string, name string, args ...string) (CmdResult, error) {
	r.record(name, args)
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	res := CmdResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
		return res, fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

func (r *ExecRunner) record(name string, args []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, name)
	for _, a := range args {
		if strings.ContainsAny(a, " \t\n\"'") {
			quoted = append(quoted, fmt.Sprintf("%q", a))
		} else {
			quoted = append(quoted, a)
		}
	}
	r.history = append(r.history, strings.Join(quoted, " "))
}

func (r *ExecRunner) History() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.history))
	copy(out, r.history)
	return out
}

// FakeRunner is a deterministic test runner matching commands by exact key or prefix.
type FakeRunner struct {
	mu        sync.Mutex
	Responses map[string]FakeResponse
	Fallback  func(name string, args []string) (CmdResult, error)
	history   []string
}

type FakeResponse struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

func NewFakeRunner() *FakeRunner {
	return &FakeRunner{
		Responses: make(map[string]FakeResponse),
	}
}

func (f *FakeRunner) On(cmdLine string, stdout string) {
	f.Responses[cmdLine] = FakeResponse{Stdout: stdout}
}

func (f *FakeRunner) OnErr(cmdLine string, stderr string, err error) {
	f.Responses[cmdLine] = FakeResponse{Stderr: stderr, ExitCode: 1, Err: err}
}

func (f *FakeRunner) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	return f.RunWithStdin(ctx, "", name, args...)
}

func (f *FakeRunner) RunWithStdin(_ context.Context, _ string, name string, args ...string) (CmdResult, error) {
	key := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.history = append(f.history, key)
	resp, ok := f.Responses[key]
	fb := f.Fallback
	f.mu.Unlock()

	if ok {
		return CmdResult{Stdout: resp.Stdout, Stderr: resp.Stderr, ExitCode: resp.ExitCode}, resp.Err
	}
	if fb != nil {
		return fb(name, args)
	}
	return CmdResult{Stderr: "not mocked: " + key, ExitCode: 1}, fmt.Errorf("fake runner: no response for %q", key)
}

func (f *FakeRunner) History() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.history))
	copy(out, f.history)
	return out
}
