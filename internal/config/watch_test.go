package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchFiresOnChange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fired := make(chan struct{}, 4)
	go func() {
		_ = Watch(ctx, p, func() { fired <- struct{}{} })
	}()

	// Let the watcher install before mutating the file.
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(p, []byte("a: 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-fired:
		// success: onChange ran after the debounce window
	case <-time.After(debounceWindow + 3*time.Second):
		t.Fatal("watcher did not fire onChange after a config write")
	}
}
