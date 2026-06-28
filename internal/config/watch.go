package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

// debounceWindow is how long the watcher waits for the config file to stop
// changing before invoking onChange. Editors and atomic saves emit several
// events in quick succession; debouncing coalesces them into one reload.
const debounceWindow = 2 * time.Second

// Watch calls onChange a short time after the config file at path changes. It
// watches the file's parent directory (so atomic saves via rename, which swap
// the inode, are still observed) and filters to events naming the config file.
// It blocks until ctx is done, then returns ctx.Err() (or a setup error).
func Watch(ctx context.Context, path string, onChange func()) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()

	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if err := w.Add(dir); err != nil {
		return err
	}

	// A stopped timer with a drained channel; reset on each relevant event.
	timer := time.NewTimer(debounceWindow)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			if filepath.Base(ev.Name) != base {
				continue
			}
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			// (Re)start the debounce window.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(debounceWindow)
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			slog.Warn("config watch error", "err", err)
		case <-timer.C:
			onChange()
		}
	}
}
