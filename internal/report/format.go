package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// FormatOptions controls output rendering.
type FormatOptions struct {
	Format  string // text | markdown | json
	Color   bool
	Verbose bool
}

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
	ansiBold   = "\033[1m"
)

// Write renders the report to w in the requested format.
func Write(w io.Writer, r *Report, opts FormatOptions) error {
	switch strings.ToLower(opts.Format) {
	case "", "text":
		return writeText(w, r, opts)
	case "markdown", "md":
		return writeMarkdown(w, r, opts)
	case "json":
		return writeJSON(w, r)
	default:
		return fmt.Errorf("unsupported format %q (expected text, markdown, or json)", opts.Format)
	}
}

func writeJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeText(w io.Writer, r *Report, opts FormatOptions) error {
	c := func(code, s string) string {
		if !opts.Color {
			return s
		}
		return code + s + ansiReset
	}

	verdictColor := ansiGreen
	switch r.Summary.Verdict {
	case "BROKEN":
		verdictColor = ansiRed
	case "DEGRADED":
		verdictColor = ansiYellow
	}

	header := fmt.Sprintf("mesh-debug %s", r.Command)
	if r.Namespace != "" {
		header += fmt.Sprintf(" (ns=%s", r.Namespace)
		if r.Target != "" {
			header += fmt.Sprintf(", target=%s", r.Target)
		}
		if r.Mode != "" {
			header += fmt.Sprintf(", mode=%s", r.Mode)
		}
		header += ")"
	}
	fmt.Fprintf(w, "%s  verdict=%s\n", c(ansiBold, header), c(verdictColor+ansiBold, r.Summary.Verdict))
	fmt.Fprintf(w, "checks: total=%d pass=%d warn=%d fail=%d info=%d skip=%d | probe=%v\n",
		r.Summary.Total, r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Info, r.Summary.Skip, r.ProbeMode)

	if len(r.Metadata) > 0 {
		keys := make([]string, 0, len(r.Metadata))
		for k := range r.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%s", k, r.Metadata[k]))
		}
		fmt.Fprintf(w, "%s\n", c(ansiGray, strings.Join(parts, " | ")))
	}
	fmt.Fprintln(w)

	currentLayer := ""
	for _, chk := range r.Checks {
		if chk.Layer != currentLayer {
			if currentLayer != "" {
				fmt.Fprintln(w)
			}
			currentLayer = chk.Layer
			fmt.Fprintf(w, "%s\n", c(ansiBold+ansiCyan, "=== "+currentLayer+" ==="))
		}
		badge := formatStatusBadge(chk.Status, opts.Color)
		res := ""
		if chk.Resource != "" {
			res = " " + c(ansiGray, "["+chk.Resource+"]")
		}
		fmt.Fprintf(w, "%s %s%s: %s\n", badge, chk.Title, res, chk.Message)
		for _, d := range chk.Details {
			fmt.Fprintf(w, "       %s\n", d)
		}
		for _, ev := range chk.Evidence {
			for _, line := range strings.Split(strings.TrimRight(ev, "\n"), "\n") {
				fmt.Fprintf(w, "       %s %s\n", c(ansiGray, "|"), line)
			}
		}
		if chk.Suggestion != "" && (chk.Status == StatusFail || chk.Status == StatusWarn) {
			fmt.Fprintf(w, "       %s %s\n", c(ansiYellow, "->"), chk.Suggestion)
		}
	}

	if len(r.NextActions) > 0 {
		fmt.Fprintf(w, "\n%s\n", c(ansiBold, "=== Recommended Actions ==="))
		for i, act := range r.NextActions {
			fmt.Fprintf(w, " %d. %s\n", i+1, act)
		}
	}

	if opts.Verbose && len(r.Commands) > 0 {
		fmt.Fprintf(w, "\n%s\n", c(ansiGray, "=== Executed Commands ==="))
		for _, cmd := range r.Commands {
			fmt.Fprintf(w, "  $ %s\n", cmd)
		}
	}
	return nil
}

func formatStatusBadge(s Status, color bool) string {
	raw := fmt.Sprintf("[%-4s]", string(s))
	if !color {
		return raw
	}
	switch s {
	case StatusPass:
		return ansiGreen + raw + ansiReset
	case StatusWarn:
		return ansiYellow + raw + ansiReset
	case StatusFail:
		return ansiRed + ansiBold + raw + ansiReset
	case StatusInfo:
		return ansiCyan + raw + ansiReset
	default:
		return ansiGray + raw + ansiReset
	}
}

func writeMarkdown(w io.Writer, r *Report, opts FormatOptions) error {
	fmt.Fprintf(w, "# mesh-debug %s — `%s`\n\n", r.Command, r.Summary.Verdict)
	if r.Namespace != "" {
		fmt.Fprintf(w, "- **Namespace:** `%s`\n", r.Namespace)
	}
	if r.Target != "" {
		fmt.Fprintf(w, "- **Target:** `%s`\n", r.Target)
	}
	if r.Mode != "" {
		fmt.Fprintf(w, "- **Mode:** `%s`\n", r.Mode)
	}
	fmt.Fprintf(w, "- **Summary:** %d PASS, %d WARN, %d FAIL, %d INFO, %d SKIP (probe=%v)\n\n",
		r.Summary.Pass, r.Summary.Warn, r.Summary.Fail, r.Summary.Info, r.Summary.Skip, r.ProbeMode)

	currentLayer := ""
	for _, chk := range r.Checks {
		if chk.Layer != currentLayer {
			currentLayer = chk.Layer
			fmt.Fprintf(w, "## %s\n\n", currentLayer)
		}
		res := ""
		if chk.Resource != "" {
			res = fmt.Sprintf(" (`%s`)", chk.Resource)
		}
		fmt.Fprintf(w, "- **[%s]** %s%s: %s\n", chk.Status, chk.Title, res, chk.Message)
		for _, d := range chk.Details {
			fmt.Fprintf(w, "  - %s\n", d)
		}
		if len(chk.Evidence) > 0 {
			fmt.Fprintln(w, "  ```text")
			for _, ev := range chk.Evidence {
				for _, line := range strings.Split(strings.TrimRight(ev, "\n"), "\n") {
					fmt.Fprintf(w, "  %s\n", line)
				}
			}
			fmt.Fprintln(w, "  ```")
		}
		if chk.Suggestion != "" && (chk.Status == StatusFail || chk.Status == StatusWarn) {
			fmt.Fprintf(w, "  - **Fix:** %s\n", chk.Suggestion)
		}
	}

	if len(r.NextActions) > 0 {
		fmt.Fprintln(w, "\n## Recommended Actions")
		for i, act := range r.NextActions {
			fmt.Fprintf(w, "%d. %s\n", i+1, act)
		}
	}

	if opts.Verbose && len(r.Commands) > 0 {
		fmt.Fprintln(w, "\n## Executed Commands")
		fmt.Fprintln(w, "```bash")
		for _, cmd := range r.Commands {
			fmt.Fprintln(w, cmd)
		}
		fmt.Fprintln(w, "```")
	}
	return nil
}
