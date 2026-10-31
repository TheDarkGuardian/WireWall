package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/TheDarkGuardian/WireWall/internal/control"
)

func metrics(args []string) error {
	f := flag.NewFlagSet("metrics", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:9878", "loopback read-only Prometheus endpoint")
	socket := f.String("socket", "/run/wirewall/control.sock", "private agent Unix socket")
	if err := f.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("metrics HTTP yalnız loopback üzerinde yayınlanır")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return serveHTTP(ctx, *listen, control.NewMetricsHandler(*socket), "metrics", "")
}
