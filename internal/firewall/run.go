package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// runner executes an external command and returns its combined output. It is
// a package variable so tests can substitute a fake implementation.
var runner = func(name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// listRunner is the cancelable counterpart to runner, used by the List() read
// paths so a hung firewall query (e.g. ipset/nft) can be aborted via context.
// Kept separate from runner so the short, idempotent Setup/Ban/Teardown commands
// stay untouched.
var listRunner = func(ctx context.Context, name string, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// run executes a command, wrapping failures with the command line and output.
func run(name string, args ...string) error {
	out, err := runner(name, args...)
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, out)
	}
	return nil
}

// runOK reports whether a command exits zero, discarding its output. Used for
// idempotency checks (e.g. iptables -C).
func runOK(name string, args ...string) bool {
	_, err := runner(name, args...)
	return err == nil
}
