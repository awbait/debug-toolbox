package report

import (
	"time"
)

// Status represents the outcome of a single diagnostic check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
	StatusInfo Status = "INFO"
	StatusSkip Status = "SKIP"
)

// Check is a single diagnostic step with human-readable and machine-readable details.
type Check struct {
	ID         string   `json:"id"`
	Layer      string   `json:"layer"`
	Title      string   `json:"title"`
	Status     Status   `json:"status"`
	Resource   string   `json:"resource,omitempty"`
	Message    string   `json:"message"`
	Details    []string `json:"details,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Suggestion string   `json:"suggestion,omitempty"`
	Commands   []string `json:"commands,omitempty"`
}

// Summary aggregates check counts and overall verdict.
type Summary struct {
	Total   int    `json:"total"`
	Pass    int    `json:"pass"`
	Warn    int    `json:"warn"`
	Fail    int    `json:"fail"`
	Info    int    `json:"info"`
	Skip    int    `json:"skip"`
	Verdict string `json:"verdict"` // HEALTHY | DEGRADED | BROKEN
}

// Report is the top-level diagnostic result suitable for humans and LLMs.
type Report struct {
	Tool        string            `json:"tool"`
	Version     string            `json:"version"`
	Command     string            `json:"command"`
	Namespace   string            `json:"namespace,omitempty"`
	Target      string            `json:"target,omitempty"`
	Mode        string            `json:"mode,omitempty"`
	ProbeMode   bool              `json:"probe_mode"`
	GeneratedAt time.Time         `json:"generated_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Summary     Summary           `json:"summary"`
	Checks      []Check           `json:"checks"`
	NextActions []string          `json:"next_actions,omitempty"`
	Commands    []string          `json:"commands,omitempty"`
}

// New creates a new diagnostic report.
func New(version, command, namespace, target string, probeMode bool) *Report {
	return &Report{
		Tool:        "mesh-debug",
		Version:     version,
		Command:     command,
		Namespace:   namespace,
		Target:      target,
		ProbeMode:   probeMode,
		GeneratedAt: time.Now().UTC(),
		Metadata:    make(map[string]string),
		Checks:      make([]Check, 0, 16),
	}
}

// Add appends a check and updates the summary counters.
func (r *Report) Add(c Check) {
	r.Checks = append(r.Checks, c)
	r.Summary.Total++
	switch c.Status {
	case StatusPass:
		r.Summary.Pass++
	case StatusWarn:
		r.Summary.Warn++
	case StatusFail:
		r.Summary.Fail++
	case StatusInfo:
		r.Summary.Info++
	case StatusSkip:
		r.Summary.Skip++
	}
	r.updateVerdict()
}

// Pass is a convenience helper to add a PASS check.
func (r *Report) Pass(id, layer, resource, title, msg string, details ...string) {
	r.Add(Check{
		ID:       id,
		Layer:    layer,
		Resource: resource,
		Title:    title,
		Status:   StatusPass,
		Message:  msg,
		Details:  details,
	})
}

// Warn is a convenience helper to add a WARN check.
func (r *Report) Warn(id, layer, resource, title, msg, suggestion string, details ...string) {
	r.Add(Check{
		ID:         id,
		Layer:      layer,
		Resource:   resource,
		Title:      title,
		Status:     StatusWarn,
		Message:    msg,
		Suggestion: suggestion,
		Details:    details,
	})
}

// Fail is a convenience helper to add a FAIL check.
func (r *Report) Fail(id, layer, resource, title, msg, suggestion string, evidence ...string) {
	r.Add(Check{
		ID:         id,
		Layer:      layer,
		Resource:   resource,
		Title:      title,
		Status:     StatusFail,
		Message:    msg,
		Suggestion: suggestion,
		Evidence:   evidence,
	})
}

// Info is a convenience helper to add an INFO check.
func (r *Report) Info(id, layer, resource, title, msg string, details ...string) {
	r.Add(Check{
		ID:       id,
		Layer:    layer,
		Resource: resource,
		Title:    title,
		Status:   StatusInfo,
		Message:  msg,
		Details:  details,
	})
}

// Skip is a convenience helper to add a SKIP check.
func (r *Report) Skip(id, layer, resource, title, msg string) {
	r.Add(Check{
		ID:       id,
		Layer:    layer,
		Resource: resource,
		Title:    title,
		Status:   StatusSkip,
		Message:  msg,
	})
}

// Finalize computes deduplicated next actions and final verdict.
func (r *Report) Finalize(executedCommands []string, includeCommands bool) {
	r.updateVerdict()
	seen := make(map[string]bool)
	r.NextActions = nil
	// Prioritize FAIL suggestions first, then WARN.
	for _, st := range []Status{StatusFail, StatusWarn} {
		for _, c := range r.Checks {
			if c.Status == st && c.Suggestion != "" && !seen[c.Suggestion] {
				seen[c.Suggestion] = true
				r.NextActions = append(r.NextActions, c.Suggestion)
			}
		}
	}
	if includeCommands && len(executedCommands) > 0 {
		r.Commands = executedCommands
	}
}

func (r *Report) updateVerdict() {
	switch {
	case r.Summary.Fail > 0:
		r.Summary.Verdict = "BROKEN"
	case r.Summary.Warn > 0:
		r.Summary.Verdict = "DEGRADED"
	default:
		r.Summary.Verdict = "HEALTHY"
	}
}

// ExitCode returns 0 when healthy/degraded, 2 when broken (FAIL checks present).
func (r *Report) ExitCode() int {
	if r.Summary.Fail > 0 {
		return 2
	}
	return 0
}
