package source

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// defaultDockerSocket is the Docker Engine API unix socket used when a docker
// source does not override it.
const defaultDockerSocket = "/var/run/docker.sock"

// newDockerAPISource streams a container's logs from the Docker Engine API over
// the unix socket — pure Go, no docker CLI. It is the "internal" docker source.
func newDockerAPISource(name, socketPath, target string, re *regexp.Regexp, ipIdx int, follow bool) *streamSource {
	return &streamSource{
		name:  name,
		re:    re,
		ipIdx: ipIdx,
		open:  dockerLogsOpener(newSocketClient(socketPath), target, follow),
		demux: autoFrame,
	}
}

// newSocketClient returns an *http.Client that dials the Docker unix socket
// regardless of the request URL's host. No overall timeout: a followed log
// stream is long-lived and is bounded by context instead.
func newSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				// Bound the dial so a hung daemon socket can't block forever.
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "unix", socketPath)
			},
			DisableCompression: true,
			// One long-lived stream per client; don't pool idle connections
			// (avoids leaking fds/goroutines when a source restarts).
			DisableKeepAlives: true,
		},
		Timeout: 0,
	}
}

// dockerLogsOpener streams GET /containers/<id>/logs?follow=1 from the daemon.
// The "docker" host in the URL is a placeholder; the transport routes every
// request to the unix socket.
func dockerLogsOpener(client *http.Client, target string, follow bool) opener {
	followN := 0
	if follow {
		followN = 1
	}
	return func(ctx context.Context) (io.ReadCloser, error) {
		u := fmt.Sprintf("http://docker/containers/%s/logs?follow=%d&stdout=1&stderr=1&tail=100",
			url.PathEscape(target), followN)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("docker api: %s for container %q", resp.Status, target)
		}
		return resp.Body, nil
	}
}

// needsDemux reports whether the buffered stream looks like Docker stdcopy
// multiplexing: an 8-byte header whose first byte is a stream id in {0,1,2} and
// whose next three bytes are zero. Raw log text effectively never starts that
// way. The peeked bytes are not consumed.
func needsDemux(br *bufio.Reader) bool {
	h, err := br.Peek(4)
	if err != nil || len(h) < 4 {
		return false
	}
	return h[0] <= 2 && h[1] == 0 && h[2] == 0 && h[3] == 0
}

// stdDemuxReader strips Docker's 8-byte stdcopy frame headers
// ([stream:1][000][size:uint32 BE]), exposing only payload bytes. Wrap it in a
// bufio.Scanner to recover log lines (payloads may contain or split lines).
type stdDemuxReader struct {
	src       io.Reader
	hdr       [8]byte
	remaining int // payload bytes left in the current frame
}

func newStdDemuxReader(src io.Reader) *stdDemuxReader {
	return &stdDemuxReader{src: src}
}

func (d *stdDemuxReader) Read(p []byte) (int, error) {
	// Per io.Reader: a zero-length read returns immediately without consuming
	// the stream (otherwise we'd eat a frame header and corrupt state).
	if len(p) == 0 {
		return 0, nil
	}
	// Skip past any zero-length frames so we never return (0, nil) for a
	// non-empty p — that would violate io.Reader and can stall bufio.
	for d.remaining == 0 {
		if _, err := io.ReadFull(d.src, d.hdr[:]); err != nil {
			return 0, err // io.EOF / io.ErrUnexpectedEOF propagate
		}
		// Validate the stdcopy header (stream id in {0,1,2}, padding zero) on
		// every frame so a desynced/garbage stream fails fast instead of
		// reading a bogus size or silently skipping data.
		if d.hdr[0] > 2 || d.hdr[1] != 0 || d.hdr[2] != 0 || d.hdr[3] != 0 {
			return 0, fmt.Errorf("docker api: corrupt frame header")
		}
		// Guard the uint32→int cast: on 32-bit builds (armv7) a size >= 2^31
		// would overflow to a negative remaining and panic the p[:n] slice.
		// A frame that large is never legitimate; treat it as a corrupt stream.
		size := binary.BigEndian.Uint32(d.hdr[4:8])
		if size > 0x7fffffff {
			return 0, fmt.Errorf("docker api: frame size %d too large (corrupt stream?)", size)
		}
		d.remaining = int(size)
	}
	n := len(p)
	if n > d.remaining {
		n = d.remaining
	}
	m, err := d.src.Read(p[:n])
	d.remaining -= m
	return m, err
}
