// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package common

import (
	"log"
	"net"
)

const MsgBufSize = 2048

func ReadHandshake(c *net.UnixConn) error {
	b := make([]byte, 1)
	_, _, _, _, err := c.ReadMsgUnix(b, nil)
	return err
}

func WriteHandshake(c *net.UnixConn) error {
	b := make([]byte, 1)
	_, _, err := c.WriteMsgUnix(b, nil, nil)
	return err
}

type DefaultLogger struct{}

func (DefaultLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
