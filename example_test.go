// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package snide_test

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tsavola/snide"
)

func Example() {
	l, err := snide.Listen("example.sock")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		l.Close()
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s\n", r.TLS.ServerName)
	})

	log.Fatal(http.ServeTLS(l, nil, "cert.pem", "key.pem"))
}
