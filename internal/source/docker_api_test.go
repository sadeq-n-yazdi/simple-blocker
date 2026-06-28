package source

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
	"time"
)

// frame builds a Docker stdcopy frame: [stream:1][000][size:uint32 BE][payload].
func frame(stream byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:8], uint32(len(payload)))
	copy(b[8:], payload)
	return b
}

// scanDemux runs bytes through the demux reader + scanner and returns the lines.
func scanDemux(t *testing.T, raw []byte) ([]string, error) {
	t.Helper()
	r := newStdDemuxReader(bytes.NewReader(raw))
	sc := bufio.NewScanner(r)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func TestDemuxMultiLineFrame(t *testing.T) {
	lines, err := scanDemux(t, frame(1, "a 1.1.1.1\nb 2.2.2.2\n"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 2 || lines[0] != "a 1.1.1.1" || lines[1] != "b 2.2.2.2" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDemuxLineSplitAcrossFrames(t *testing.T) {
	raw := append(frame(1, "hel"), frame(1, "lo world\n")...)
	lines, err := scanDemux(t, raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 1 || lines[0] != "hello world" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDemuxStdoutStderrInterleave(t *testing.T) {
	raw := append(frame(1, "out 1.1.1.1\n"), frame(2, "err 2.2.2.2\n")...)
	lines, err := scanDemux(t, raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected both streams, got %q", lines)
	}
}

func TestDemuxZeroLengthFrame(t *testing.T) {
	raw := append(frame(1, ""), frame(1, "x 3.3.3.3\n")...)
	lines, err := scanDemux(t, raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 1 || lines[0] != "x 3.3.3.3" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDemuxManyZeroLengthFrames(t *testing.T) {
	// >100 consecutive empty frames would trip bufio's ErrNoProgress if Read
	// returned (0, nil); the internal loop must skip them all.
	var raw []byte
	for i := 0; i < 200; i++ {
		raw = append(raw, frame(1, "")...)
	}
	raw = append(raw, frame(1, "x 4.4.4.4\n")...)
	lines, err := scanDemux(t, raw)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(lines) != 1 || lines[0] != "x 4.4.4.4" {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDemuxTruncatedHeader(t *testing.T) {
	// 5 bytes is less than the 8-byte header → ErrUnexpectedEOF.
	_, err := scanDemux(t, []byte{1, 0, 0, 0, 5})
	if err == nil {
		t.Fatal("expected error on truncated header")
	}
}

func TestNeedsDemux(t *testing.T) {
	muxed := frame(1, "1.2.3.4 GET /x\n")
	br := bufio.NewReader(bytes.NewReader(muxed))
	if !needsDemux(br) {
		t.Error("multiplexed stream should need demux")
	}
	// Peek must not consume: a full read still sees the header byte.
	first, _ := br.ReadByte()
	if first != 1 {
		t.Errorf("Peek consumed bytes: first = %d", first)
	}

	raw := bufio.NewReader(bytes.NewReader([]byte("1.2.3.4 GET /x\n")))
	if needsDemux(raw) {
		t.Error("raw text should not need demux")
	}
}

func TestStreamSourceEndToEndDemux(t *testing.T) {
	// A fake opener feeds framed bytes; autoFrame must demux and the regex must
	// report the IPs.
	raw := append(frame(1, "Invalid user a from 10.0.0.1 port 22\n"),
		frame(2, "Invalid user b from 10.0.0.2 port 22\n")...)
	re := regexp.MustCompile(`from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	s := &streamSource{
		name:  "fake",
		re:    re,
		ipIdx: 1,
		open: func(ctx context.Context) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(raw)), nil
		},
		demux: autoFrame,
	}

	var got []string
	err := s.stream(context.Background(), func(ip, _ string) { got = append(got, ip) })
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	sort.Strings(got)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Fatalf("reported IPs = %q", got)
	}
}

// TestDockerLogsOpenerOverSocket exercises the real path end-to-end without a
// Docker daemon: a stdlib HTTP server on a unix socket serves a multiplexed log
// stream, and the source dials it through newSocketClient + dockerLogsOpener.
func TestDockerLogsOpenerOverSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/web/logs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("follow") != "1" {
			t.Errorf("missing follow=1: %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
		w.Write(frame(1, "Invalid user x from 172.16.0.9 port 22\n"))
		// Returning closes the response body, ending the stream.
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	re := regexp.MustCompile(`from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	s := newDockerAPISource("web", sock, "web", re, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var got []string
	if err := s.stream(ctx, func(ip, _ string) { got = append(got, ip) }); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(got) != 1 || got[0] != "172.16.0.9" {
		t.Fatalf("reported = %q", got)
	}
}

func TestDockerLogsOpenerNon200(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/containers/missing/logs", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no such container", http.StatusNotFound)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	open := dockerLogsOpener(newSocketClient(sock), "missing")
	if _, err := open(context.Background()); err == nil {
		t.Fatal("expected error for 404 response")
	}
}

func TestStreamSourceRawMode(t *testing.T) {
	// rawFrame must NOT demux: plain text lines pass through unchanged.
	re := regexp.MustCompile(`(?P<ip>\d{1,3}(?:\.\d{1,3}){3})`)
	s := &streamSource{
		name:  "raw",
		re:    re,
		ipIdx: 1,
		open: func(ctx context.Context) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader([]byte("hit 9.9.9.9\n"))), nil
		},
		demux: rawFrame,
	}
	var got []string
	if err := s.stream(context.Background(), func(ip, _ string) { got = append(got, ip) }); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(got) != 1 || got[0] != "9.9.9.9" {
		t.Fatalf("reported = %q", got)
	}
}
