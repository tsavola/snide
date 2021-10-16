// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package snide provides a network connection listener for implementing
// backend servers.  Subpackage proxy provides its counterpart.
package snide

import (
	"net"
	"os"

	"github.com/tsavola/mu"
)

// Listener for proxied TLS connections.  Accepting a connection yields the
// underlying encrypted connection, so this is to be used with an API such as
// net/http.ServeTLS or crypto/tls.Server.
type Listener struct {
	meta *net.UnixListener

	mu     mu.Mutex
	accept *Acceptor
	wait   <-chan struct{}
	closed chan struct{}
}

// Listen creates a unixpacket socket in the filesystem.
func Listen(path string) (*Listener, error) {
	addr := &net.UnixAddr{
		Net:  "unixpacket",
		Name: path,
	}

	meta, err := net.ListenUnix(addr.Net, addr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		meta:   meta,
		closed: make(chan struct{}),
	}
	return l, nil
}

// Accept a connection.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		var (
			accept *Acceptor
			wait   <-chan struct{}
			closed <-chan struct{}
		)

		l.mu.Guard(func() {
			closed = l.closed
			if closed == nil {
				return
			}

			if l.accept != nil {
				accept = l.accept
			} else {
				if l.wait == nil {
					c := make(chan struct{})
					go l.metaAccept(c)
					l.wait = c
				}
				wait = l.wait
			}
		})

		if closed == nil {
			return nil, os.ErrClosed
		}

		if accept != nil {
			if conn, err := accept.Accept(); err == nil {
				return conn, nil
			}

			l.mu.Guard(func() {
				if l.accept == accept {
					l.accept = nil
				} else {
					accept = nil
				}
			})
			if accept != nil {
				accept.Close()
			}
		} else {
			select {
			case <-wait:
			case <-closed:
				return nil, os.ErrClosed
			}
		}
	}
}

// Addr is not descriptive.
func (l *Listener) Addr() net.Addr {
	return dummyAddr
}

// Close the listener and remove the socket from the filesystem.
func (l *Listener) Close() error {
	var a *Acceptor
	var c chan<- struct{}

	l.mu.Guard(func() {
		a = l.accept
		c = l.closed
		l.accept = nil
		l.closed = nil
	})

	if c != nil {
		close(c)
	}
	if a != nil {
		a.Close()
	}

	return l.meta.Close()
}

func (l *Listener) metaAccept(wait chan<- struct{}) {
	defer close(wait)

	var accept *Acceptor

	defer func() {
		l.mu.Guard(func() {
			if l.closed != nil {
				l.accept = accept
				accept = nil
			}
			l.wait = nil
		})
		if accept != nil {
			accept.Close()
		}
	}()

	conn, err := l.meta.AcceptUnix()
	if err != nil {
		return
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	a, err := NewAcceptor(conn)
	if err != nil {
		return
	}

	accept = a
	conn = nil
}
