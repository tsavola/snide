// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snide

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/tsavola/snide/internal/common"
)

// Acceptor is a listener for proxied TLS connections.  It requires a
// separately established unixpacket connection to the proxy.  It is
// operational until the connection is terminated.
type Acceptor struct {
	conn *net.UnixConn
	oob  [24]byte
}

// NewAcceptor takes ownership of a connection.  The connection must use the
// unixpacket protocol.
func NewAcceptor(conn *net.UnixConn) (*Acceptor, error) {
	if err := common.ReadHandshake(conn); err != nil {
		return nil, err
	}
	if err := common.WriteHandshake(conn); err != nil {
		return nil, err
	}

	return &Acceptor{conn: conn}, nil
}

// Accept a connection.
func (a *Acceptor) Accept() (net.Conn, error) {
	buf := make([]byte, common.MsgBufSize)

	n, oobn, flags, _, err := a.conn.ReadMsgUnix(buf, a.oob[:])
	if err != nil {
		return nil, err
	}

	buf = buf[:n]

	cmsgs, err := syscall.ParseSocketControlMessage(a.oob[:oobn])
	if err != nil {
		return nil, err
	}

	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()

	for i := range cmsgs {
		fds, err := syscall.ParseUnixRights(&cmsgs[i])
		if err != nil {
			return nil, err
		}

		for _, fd := range fds {
			files = append(files, os.NewFile(uintptr(fd), strconv.Itoa(fd)))
		}
	}

	if len(files) != 1 {
		return nil, errors.New("received wrong number of file descriptors")
	}
	if flags&syscall.MSG_TRUNC != 0 {
		return nil, errors.New("message truncated")
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		return nil, errors.New("control data truncated")
	}

	local, buf, err := popAddr(buf)
	if err != nil {
		return nil, err
	}
	remote, buf, err := popAddr(buf)
	if err != nil {
		return nil, err
	}

	fileConn, err := net.FileConn(files[0])
	if err != nil {
		return nil, err
	}

	conn := &connWrapper{
		Reader: io.MultiReader(bytes.NewReader(buf), fileConn),
		Conn:   fileConn,
		local:  local,
		remote: remote,
	}
	return conn, nil
}

// Addr is not descriptive.
func (a *Acceptor) Addr() net.Addr {
	return dummyAddr
}

// Close the listener (and the associated connection).
func (a *Acceptor) Close() error {
	return a.conn.Close()
}

func popAddr(buf []byte) (net.Addr, []byte, error) {
	network, buf, err := popString(buf)
	if err != nil {
		return nil, nil, err
	}

	address, buf, err := popString(buf)
	if err != nil {
		return nil, nil, err
	}

	return &addr{network, address}, buf, nil
}

func popString(buf []byte) (string, []byte, error) {
	if len(buf) < 2 {
		return "", nil, errors.New("invalid encoding")
	}
	n := int(binary.LittleEndian.Uint16(buf))
	buf = buf[2:]

	if len(buf) < n {
		return "", nil, errors.New("invalid encoding")
	}
	s := string(buf[:n])
	buf = buf[n:]

	return s, buf, nil
}

type connWrapper struct {
	io.Reader
	net.Conn
	local  net.Addr
	remote net.Addr
}

func (c *connWrapper) Read(b []byte) (int, error) { return c.Reader.Read(b) }
func (c *connWrapper) LocalAddr() net.Addr        { return c.local }
func (c *connWrapper) RemoteAddr() net.Addr       { return c.remote }
