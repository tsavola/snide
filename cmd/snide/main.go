// Copyright (c) 2020 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/tsavola/confi"
	"github.com/tsavola/snide/proxy"
)

const (
	DefaultFrontendNet      = "tcp"
	DefaultFrontendAddr     = ":443"
	DefaultTimeoutProxy     = time.Second * 30
	DefaultTimeoutHandshake = time.Second * 10
	DefaultTimeoutShutdown  = time.Second * 5
)

type Config struct {
	Frontend struct {
		Net  string
		Addr string
	}

	Timeout struct {
		Proxy     time.Duration
		Handshake time.Duration
		Shutdown  time.Duration
	}

	Backend []proxy.BackendConfig
}

var config = new(Config)

func main() {
	log.SetFlags(0)
	if err := mainError(); err != nil {
		log.Fatal(err)
	}
}

func mainError() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var frontend net.Listener

	listeners, err := activation.Listeners()
	if err != nil {
		return err
	}
	for i, l := range listeners {
		if l != nil {
			if i == 0 {
				frontend = l
			} else {
				return errors.New("invalid socket activation configuration")
			}
		}
	}

	if frontend == nil {
		config.Frontend.Net = DefaultFrontendNet
		config.Frontend.Addr = DefaultFrontendAddr
	}
	config.Timeout.Proxy = DefaultTimeoutProxy
	config.Timeout.Handshake = DefaultTimeoutHandshake
	config.Timeout.Shutdown = DefaultTimeoutShutdown

	conf := confi.NewBuffer()
	flag.Var(conf.FileReader(), "f", "read a configuration file")
	flag.Var(conf.DirReader("*.toml"), "d", "read configuration files from a directory")
	flag.Var(conf.Assigner(), "o", "set a configuration option (path.to.key=value)")
	flag.Usage = confi.FlagUsage(nil, config)
	flag.Parse()
	if err := conf.Apply(config); err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "%s: %v\n", flag.CommandLine.Name(), err)
		os.Exit(2)
	}

	if config.Timeout.Proxy > 0 && config.Timeout.Handshake > 0 {
		if config.Timeout.Proxy < config.Timeout.Handshake {
			return errors.New("configured proxy timeout is shorter than handshake timeout")
		}
	}

	if len(config.Backend) == 0 {
		return errors.New("no backends configured")
	}
	backends, err := proxy.New(nil, config.Backend, nil)
	if err != nil {
		return err
	}

	if frontend == nil {
		frontend, err = net.Listen(config.Frontend.Net, config.Frontend.Addr)
		if err != nil {
			return err
		}
	} else if config.Frontend.Net != "" || config.Frontend.Addr != "" {
		return errors.New("explicit frontend configuration with socket activation")
	}

	if _, err := daemon.SdNotify(true, daemon.SdNotifyReady); err != nil {
		return err
	}

	ctx := context.Background()

	acceptErr := make(chan error, 1)

	workers := new(sync.WaitGroup)
	workers.Add(1)
	go func() {
		defer workers.Done()

		for {
			conn, err := frontend.Accept()
			if err != nil {
				acceptErr <- err
				break
			}

			workers.Add(1)
			go func() {
				defer workers.Done()

				ctx := ctx
				now := time.Now()

				if config.Timeout.Proxy > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, now.Add(config.Timeout.Proxy))
					defer cancel()
				}

				if config.Timeout.Handshake > 0 {
					if err := conn.SetDeadline(now.Add(config.Timeout.Handshake)); err != nil {
						panic(err)
					}
				}

				backends.Handle(ctx, conn)
			}()
		}
	}()

	select {
	case err = <-acceptErr:
	case <-signals:
	}

	daemon.SdNotify(false, daemon.SdNotifyStopping)
	frontend.Close()

	if err != nil {
		return err
	}

	var timeout <-chan time.Time
	if config.Timeout.Shutdown > 0 {
		timeout = time.NewTimer(config.Timeout.Shutdown).C
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		workers.Wait()
	}()

	select {
	case <-timeout:
	case <-done:
	}

	return nil
}
