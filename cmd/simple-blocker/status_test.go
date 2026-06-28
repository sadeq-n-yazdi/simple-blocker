package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"code.sadeq.uk/simple-blocker/internal/control"
)

func TestRenderStatus(t *testing.T) {
	snap := control.Snapshot{
		Backend:   "nftables-native",
		Bans:      []control.Ban{{IP: "10.0.0.9", ExpiresSeconds: 300}},
		Offenders: []control.Offender{{IP: "10.0.0.2", Count: 3, WouldBanSeconds: 1800}},
	}
	var buf bytes.Buffer
	renderStatus(&buf, snap, true)
	out := buf.String()
	for _, want := range []string{"nftables-native", "Banned (firewall): 1", "10.0.0.9", "Offenders (tracker): 1", "10.0.0.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
	// 10.0.0.2 is over threshold (would-ban>0) but not in the ban set → anomaly.
	if !strings.Contains(out, "NOT banned") {
		t.Errorf("expected anomaly diff line:\n%s", out)
	}
}

func TestRenderStatusFallbackNote(t *testing.T) {
	var buf bytes.Buffer
	renderStatus(&buf, control.Snapshot{Backend: "ipset+iptables", Bans: []control.Ban{}}, false)
	if !strings.Contains(buf.String(), "daemon not running") {
		t.Errorf("fallback render should note the daemon is down:\n%s", buf.String())
	}
}

func TestDiffStatus(t *testing.T) {
	snap := control.Snapshot{
		Bans: []control.Ban{
			{IP: "10.0.0.1"}, // banned & tracked (count high)
			{IP: "10.0.0.9"}, // banned but not tracked → lingering
		},
		Offenders: []control.Offender{
			{IP: "10.0.0.1", Count: 5, WouldBanSeconds: 3600}, // over threshold, banned → fine
			{IP: "10.0.0.2", Count: 3, WouldBanSeconds: 1800}, // over threshold, NOT banned → anomaly
			{IP: "10.0.0.3", Count: 1, WouldBanSeconds: 0},    // under threshold → watching
		},
	}
	anomalies, lingering, watching := diffStatus(snap)
	if !reflect.DeepEqual(anomalies, []string{"10.0.0.2"}) {
		t.Errorf("anomalies = %v", anomalies)
	}
	if !reflect.DeepEqual(lingering, []string{"10.0.0.9"}) {
		t.Errorf("lingering = %v", lingering)
	}
	if !reflect.DeepEqual(watching, []string{"10.0.0.3"}) {
		t.Errorf("watching = %v", watching)
	}
}

func TestHumanSeconds(t *testing.T) {
	if got := humanSeconds(0); got != "-" {
		t.Errorf("0 → %q", got)
	}
	if got := humanSeconds(90); got != "1m30s" {
		t.Errorf("90 → %q", got)
	}
}
