// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package proxy provides a TLS connection forwarder.  The parent package
// provides its counterpart.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/tsavola/mu"
	"github.com/tsavola/snide/internal/common"
)

const (
	minBackoff = time.Second / 5
	maxBackoff = time.Second * 5
)

type filer interface {
	File() (*os.File, error)
}

type intercepted struct{}

func (err intercepted) Error() string  { return "intercepted" }
func (err intercepted) String() string { return err.Error() }

func noCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, intercepted{}
}

type connWrapper struct {
	io.Reader
	net.Conn
}

func (c *connWrapper) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func (c *connWrapper) Write([]byte) (int, error)  { return 0, intercepted{} }
func (c *connWrapper) Close() error               { return nil }

type Logger interface {
	Printf(format string, args ...interface{})
}

type BackendConfig struct {
	Addr     string   // Socket path.
	Names    []string // Server names.  Wildcards are supported.
	Fallback bool     // The target for unknown server names.
}

// Proxy for TLS connections.
type Proxy struct {
	tlsConf  *tls.Config
	servers  map[string]*backend
	fallback *backend
	log      Logger
}

// New TLS proxy.
func New(tlsConf *tls.Config, confs []BackendConfig, logger Logger) (*Proxy, error) {
	if tlsConf == nil {
		tlsConf = new(tls.Config)
	} else {
		tlsConf = tlsConf.Clone()
	}
	if tlsConf.GetCertificate == nil {
		tlsConf.GetCertificate = noCertificate
	}

	if logger == nil {
		logger = common.DefaultLogger{}
	}

	p := &Proxy{
		tlsConf: tlsConf,
		servers: make(map[string]*backend),
		log:     logger,
	}

	addrs := make(map[string]struct{})

	for _, conf := range confs {
		if _, exist := addrs[conf.Addr]; exist {
			return nil, fmt.Errorf("duplicate address in backend configuration: %s", conf.Addr)
		}
		addrs[conf.Addr] = struct{}{}

		back := newBackend(conf.Addr, logger)

		for _, name := range conf.Names {
			if _, exist := p.servers[name]; exist {
				return nil, fmt.Errorf("duplicate server name in backend configuration: %s", name)
			}
			p.servers[name] = back
		}

		if conf.Fallback {
			if p.fallback != nil {
				return nil, errors.New("multiple fallback backends configured")
			}
			p.fallback = back
		}
	}

	return p, nil
}

// Handle a client connection.
func (p *Proxy) Handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	buf := bytes.NewBuffer(make([]byte, 0, common.MsgBufSize))

	writeAddr(buf, client.LocalAddr())
	writeAddr(buf, client.RemoteAddr())

	tlsConn := tls.Server(&connWrapper{
		Reader: io.TeeReader(client, buf),
		Conn:   client,
	}, p.tlsConf)

	if err := tlsConn.Handshake(); !errors.Is(err, intercepted{}) {
		p.log.Printf("client %s: handshake: %v", client.RemoteAddr(), err)
		return
	}

	name := tlsConn.ConnectionState().ServerName
	if name == "" {
		p.log.Printf("client %s: no server name", client.RemoteAddr())
		return
	}

	back := p.servers[name]
	if back == nil {
		back = p.fallback
	}
	if back == nil {
		p.log.Printf("client %s: unknown server name: %q", client.RemoteAddr(), name)
		return
	}

	// It would be nice to be able to avoid this file descriptor duplication.
	f, err := client.(filer).File()
	if err != nil {
		p.log.Printf("client %s (server %s): %v", client.RemoteAddr(), name, err)
		return
	}
	defer f.Close()

	oob := syscall.UnixRights(int(f.Fd()))

	for {
		c, err := back.getConn(ctx)
		if err != nil {
			p.log.Printf("client %s (server %s): %v", client.RemoteAddr(), name, err)
			return
		}

		_, _, err = c.WriteMsgUnix(buf.Bytes(), oob, nil)
		if err == nil {
			break
		}
		if !errors.Is(err, io.EOF) {
			p.log.Printf("client %s (server %s): backend %s: %v", client.RemoteAddr(), name, back.addr, err)
		}
		back.closeConn(c)
	}
}

type backend struct {
	addr string
	log  Logger

	mu      mu.Mutex
	conn    *net.UnixConn
	wait    <-chan struct{}
	backoff uint
}

func newBackend(addr string, logger Logger) *backend {
	return &backend{
		addr: addr,
		log:  logger,
	}
}

func (b *backend) getConn(ctx context.Context) (*net.UnixConn, error) {
	for {
		var conn *net.UnixConn
		var wait <-chan struct{}

		b.mu.Guard(func() {
			if b.conn != nil {
				conn = b.conn
			} else {
				if b.wait == nil {
					c := make(chan struct{})
					go b.connect(ctx, c, b.backoff)
					b.wait = c
					b.backoff++
				}
				wait = b.wait
			}
		})

		if conn != nil {
			return conn, nil
		}

		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (b *backend) closeConn(conn *net.UnixConn) {
	b.mu.Guard(func() {
		if b.conn == conn {
			b.conn = nil
		} else {
			conn = nil
		}
	})

	if conn != nil {
		conn.Close()
	}
}

func (b *backend) connect(ctx context.Context, wait chan<- struct{}, backoff uint) {
	var conn *net.UnixConn

	defer func() {
		defer close(wait)
		if conn == nil {
			d := minBackoff << backoff
			if d > maxBackoff {
				d = maxBackoff
			}
			d += time.Duration(rand.Int63n(int64(minBackoff)))
			time.Sleep(d)
		}
	}()

	defer b.mu.Guard(func() {
		b.conn = conn
		b.wait = nil
		if conn != nil {
			b.backoff = 0
		}
	})

	addr := &net.UnixAddr{
		Net:  "unixpacket",
		Name: b.addr,
	}

	c, err := net.DialUnix(addr.Net, nil, addr)
	if err != nil {
		b.log.Printf("%v", err)
		return
	}
	defer func() {
		if c != nil {
			c.Close()
		}
	}()

	t, deadline := ctx.Deadline()
	if deadline {
		if err := c.SetDeadline(t); err != nil {
			panic(err)
		}
	}

	if err := common.WriteHandshake(c); err != nil {
		b.log.Printf("backend %s: handshake: %v", b.addr, err)
		return
	}
	if err := common.ReadHandshake(c); err != nil {
		b.log.Printf("backend %s: handshake: %v", b.addr, err)
		return
	}

	if deadline {
		if err := c.SetDeadline(time.Time{}); err != nil {
			panic(err)
		}
	}

	conn = c
	c = nil
}

func writeAddr(w *bytes.Buffer, addr net.Addr) {
	writeString(w, addr.Network())
	writeString(w, addr.String())
}

func writeString(w *bytes.Buffer, s string) {
	b := []byte(s)
	n := len(b)
	if n > math.MaxUint16 {
		panic(errors.New("unreasonably long network address string"))
	}
	binary.Write(w, binary.LittleEndian, uint16(n))
	w.Write(b)
}
