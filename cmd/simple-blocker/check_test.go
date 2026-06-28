package main

import (
	"strings"
	"testing"
	"time"

	"code.sadeq.uk/simple-blocker/internal/config"
	"code.sadeq.uk/simple-blocker/internal/source"
)

func TestHighlight(t *testing.T) {
	m := source.Match{Line: "ban 1.2.3.4 now", IP: "1.2.3.4", IPStart: 4, IPEnd: 11}
	colored := highlight(m, true)
	if !strings.Contains(colored, ansiHighlight+"1.2.3.4"+ansiReset) {
		t.Errorf("expected highlighted IP, got %q", colored)
	}
	if plain := highlight(m, false); plain != m.Line {
		t.Errorf("no-color should be the raw line, got %q", plain)
	}
	// Out-of-range span must not panic and returns the line unchanged.
	bad := source.Match{Line: "short", IPStart: 2, IPEnd: 99}
	if highlight(bad, true) != "short" {
		t.Errorf("bad span should return line unchanged")
	}
}

func TestSelectSources(t *testing.T) {
	all := []config.Source{
		{Type: "journal", Name: "ssh", Target: "ssh"},
		{Type: "docker", Name: "nginx", Target: "web-1"},
	}
	if got := selectSources(all, ""); len(got) != 2 {
		t.Errorf("empty filter should return all, got %d", len(got))
	}
	if got := selectSources(all, "nginx"); len(got) != 1 || got[0].Name != "nginx" {
		t.Errorf("name filter failed: %+v", got)
	}
	if got := selectSources(all, "web-1"); len(got) != 1 || got[0].Target != "web-1" {
		t.Errorf("target filter failed: %+v", got)
	}
	if got := selectSources(all, "nope"); len(got) != 0 {
		t.Errorf("unknown filter should return none, got %d", len(got))
	}
}

func TestLowestThreshold(t *testing.T) {
	s := config.BanSchedule{
		{Offenses: 5, Ban: config.Duration(time.Hour)},
		{Offenses: 2, Ban: config.Duration(10 * time.Minute)},
	}
	if got := lowestThreshold(s); got != 2 {
		t.Errorf("lowestThreshold = %d, want 2", got)
	}
}

func TestUseColorNever(t *testing.T) {
	if useColor("never") {
		t.Error("never should disable color")
	}
	if !useColor("always") {
		t.Error("always should enable color")
	}
	t.Setenv("NO_COLOR", "1")
	if useColor("auto") {
		t.Error("auto must honor NO_COLOR")
	}
	// Presence disables color even when the value is empty (no-color.org).
	t.Setenv("NO_COLOR", "")
	if useColor("auto") {
		t.Error("auto must honor an empty-but-present NO_COLOR")
	}
}
