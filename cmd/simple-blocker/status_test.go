package main

import (
	"reflect"
	"testing"

	"code.sadeq.uk/simple-blocker/internal/control"
)

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
