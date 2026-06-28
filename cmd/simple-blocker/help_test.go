package main

import (
	"strings"
	"testing"
)

func TestCommandHelpKnownTopics(t *testing.T) {
	// Every command listed in the overview must resolve to detailed help, and
	// that help must name the command. This guards against a topic silently
	// going missing from commandHelp.
	for _, topic := range []string{"status", "check", "whitelist", "blacklist", "version"} {
		text, ok := commandHelp(topic)
		if !ok {
			t.Errorf("commandHelp(%q): not found", topic)
			continue
		}
		if !strings.Contains(text, "simple-blocker "+topic) {
			t.Errorf("commandHelp(%q): help does not mention the command", topic)
		}
	}
}

func TestCommandHelpUnknownTopic(t *testing.T) {
	if _, ok := commandHelp("definitely-not-a-command"); ok {
		t.Fatal("commandHelp returned ok for an unknown topic")
	}
}

func TestMainHelpListsEveryCommand(t *testing.T) {
	var b strings.Builder
	printMainHelp(&b)
	out := b.String()
	for _, cmd := range []string{"status", "check", "whitelist", "blacklist", "version", "help"} {
		if !strings.Contains(out, cmd) {
			t.Errorf("main help is missing command %q", cmd)
		}
	}
	// A few structural anchors so the overview stays comprehensive.
	for _, section := range []string{"USAGE:", "COMMANDS:", "DAEMON FLAGS", "EXAMPLES:"} {
		if !strings.Contains(out, section) {
			t.Errorf("main help is missing section %q", section)
		}
	}
}

func TestIsHelpArg(t *testing.T) {
	for _, a := range []string{"-h", "--help", "help"} {
		if !isHelpArg(a) {
			t.Errorf("isHelpArg(%q) = false, want true", a)
		}
	}
	// Values that must NOT be treated as help (e.g. an action, a flag value,
	// or an IP being added).
	for _, a := range []string{"", "add", "remove", "show", "1.2.3.4", "Help", "-H", "-config"} {
		if isHelpArg(a) {
			t.Errorf("isHelpArg(%q) = true, want false", a)
		}
	}
}

func TestListHelpIsListSpecific(t *testing.T) {
	wl := listHelp("whitelist")
	if !strings.Contains(wl, "never bans") || !strings.Contains(wl, `help blacklist`) {
		t.Error("whitelist help missing its description or cross-reference")
	}
	bl := listHelp("blacklist")
	if !strings.Contains(bl, "banned permanently") || !strings.Contains(bl, `help whitelist`) {
		t.Error("blacklist help missing its description or cross-reference")
	}
}
