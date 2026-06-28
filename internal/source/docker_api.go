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
)

// defaultDockerSocket is the Docker Engine API unix socket used when a docker
// source does not override it.
const defaultDockerSocket = "/var/run/docker.sock"

// newDockerAPISource streams a container's logs from the Docker Engine API over
// the unix socket — pure Go, no docker CLI. It is the "internal" docker source.
func newDockerAPISource(name, socketPath, target string, re *regexp.Regexp, ipIdx int) *streamSource {
	return &streamSource{
		name:  name,
		re:    re,
		ipIdx: ipIdx,
		open:  dockerLogsOpener(newSocketClient(socketPath), target),
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
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
			DisableCompression: true,
		},
		Timeout: 0,
	}
}

// dockerLogsOpener streams GET /containers/<id>/logs?follow=1 from the daemon.
// The "docker" host in the URL is a placeholder; the transport routes every
// request to the unix socket.
func dockerLogsOpener(client *http.Client, target string) opener {
	return func(ctx context.Context) (io.ReadCloser, error) {
		u := fmt.Sprintf("http://docker/containers/%s/logs?follow=1&stdout=1&stderr=1&tail=100",
			url.PathEscape(target))
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
	if d.remaining == 0 {
		if _, err := io.ReadFull(d.src, d.hdr[:]); err != nil {
			return 0, err // io.EOF / io.ErrUnexpectedEOF propagate
		}
		d.remaining = int(binary.BigEndian.Uint32(d.hdr[4:8]))
		if d.remaining == 0 {
			return 0, nil // zero-length frame; caller will Read again
		}
	}
	n := len(p)
	if n > d.remaining {
		n = d.remaining
	}
	m, err := d.src.Read(p[:n])
	d.remaining -= m
	return m, err
}
