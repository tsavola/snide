// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snide

import (
	"net"
)

type addr struct {
	net string
	str string
}

func (a *addr) Network() string { return a.net }
func (a *addr) String() string  { return a.str }

var dummyAddr net.Addr = &addr{"@", "@"}
