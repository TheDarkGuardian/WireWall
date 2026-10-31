package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/control"
	"github.com/TheDarkGuardian/WireWall/internal/model"
	"github.com/TheDarkGuardian/WireWall/internal/policy"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run(args []string) error {
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	switch command {
	case "version":
		fmt.Println("WireWall 0.1.0")
		return nil
	case "default-policy":
		return json.NewEncoder(os.Stdout).Encode(policy.Default())
	case "validate":
		f := flag.NewFlagSet(command, flag.ContinueOnError)
		path := f.String("policy", "", "Policy JSON file")
		if err := f.Parse(args); err != nil {
			return err
		}
		p, err := readPolicy(*path)
		if err != nil {
			return err
		}
		if err = policy.Validate(p); err != nil {
			return err
		}
		fmt.Println("Politika geçerli")
		return nil
	case "serve":
		return serve(args)
	case "agent":
		return agent(args)
	case "metrics":
		return metrics(args)
	case "render-nft":
		return renderNFT(args)
	case "rollback-guard":
		return control.RunGuard(args)
	default:
		return fmt.Errorf("bilinmeyen komut %q; serve, agent, default-policy, validate, render-nft, version", command)
	}
}
func readPolicy(path string) (model.Policy, error) {
	var p model.Policy
	if path == "" {
		return p, errors.New("--policy gerekli")
	}
	info, err := os.Stat(path)
	if err != nil {
		return p, err
	}
	if info.Size() > 1<<20 {
		return p, errors.New("politika dosyası 1 MiB sınırını aşıyor")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})))
	d.DisallowUnknownFields()
	if err = d.Decode(&p); err != nil {
		return p, err
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		return p, errors.New("politika dosyası yalnız tek JSON nesnesi içermeli")
	}
	return p, nil
}
func tokenFor(dir string) (string, error) {
	if token := os.Getenv("WIREWALL_TOKEN"); token != "" {
		if len(token) < 32 {
			return "", errors.New("WIREWALL_TOKEN en az 32 karakter olmalı")
		}
		return token, nil
	}
	path := filepath.Join(dir, "operator.token")
	raw, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(raw))
		if len(token) < 32 {
			return "", errors.New("operatör anahtar dosyası geçersiz")
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var random [32]byte
	if _, err = rand.Read(random[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random[:])
	if err = os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, err = file.WriteString(token + "\n")
	closeErr := file.Close()
	if err != nil {
		return "", err
	}
	return token, closeErr
}
func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	backend := f.String("backend", "lab", "lab, remote (unprivileged panel), or xdp (diagnostic)")
	socket := f.String("socket", "/run/wirewall/control.sock", "privileged agent Unix socket for remote backend")
	listen := f.String("listen", "127.0.0.1:8080", "loopback HTTP address")
	data := f.String("data", "data", "private state directory")
	web := f.String("web", "web/dist", "compiled web directory")
	path := f.String("policy", "", "optional initial policy JSON; required for xdp")
	iface := f.String("interface", "", "override interface")
	xdpMode := f.String("xdp-mode", "", "native or generic")
	object := f.String("object", "bpf/wirewall_bpfel.o", "compiled XDP object")
	confirm := f.Bool("confirm-network-changes", false, "explicitly enable real Linux firewall mutation")
	replace := f.Bool("replace-policy", false, "explicitly replace persisted policy with --policy file")
	if err := f.Parse(args); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("HTTP yalnız loopback üzerinde yayınlanır; uzaktan erişim için SSH tüneli kullanın")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *backend == "remote" {
		if *path != "" || *iface != "" || *xdpMode != "" || *confirm || *replace {
			return errors.New("remote panel politika yüklemez; ağ seçeneklerini agent sürecinde kullanın")
		}
		token, e := tokenFor(*data)
		if e != nil {
			return e
		}
		return serveHTTP(ctx, *listen, control.NewProxyHTTP(token, *socket, *web).Handler(), "remote", *data)
	}
	if *backend != "lab" && *backend != "xdp" {
		return errors.New("backend lab, remote veya xdp olmalı")
	}
	if *backend == "xdp" && (*path == "" || !*confirm) {
		return errors.New("gerçek mod --policy ve --confirm-network-changes gerektirir; önce laboratuvar/Ubuntu test rehberini okuyun")
	}
	var ownership *control.NetworkOwnership
	if *backend == "xdp" {
		var err error
		ownership, err = control.AcquireNetworkOwnership(*data)
		if err != nil {
			return err
		}
		defer ownership.Close()
	}
	store, err := control.OpenStore(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	initial, err := startupPolicy(store, *path, *replace, *iface, *xdpMode)
	if err != nil {
		return err
	}
	service, err := control.NewService(store, initial, *backend)
	if err != nil {
		return err
	}
	defer service.Close()
	if *backend == "xdp" {
		live, e := control.NewXDPRuntime(ctx, service.Policy(), service.Bans(), *object, *data, ownership)
		if e != nil {
			return e
		}
		service.SetRuntime(live)
	}
	token, err := tokenFor(*data)
	if err != nil {
		return err
	}
	handler := control.NewHTTP(service, token, *web).Handler()
	done := make(chan struct{})
	go func() { defer close(done); service.Run(ctx) }()
	defer func() { cancel(); <-done }()
	return serveHTTP(ctx, *listen, handler, *backend, *data)
}

func serveHTTP(ctx context.Context, listen string, handler http.Handler, backend, data string) error {
	server := &http.Server{Addr: listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 16}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	if backend == "metrics" {
		log.Printf("WireWall read-only metrics: http://%s/metrics", listen)
	} else {
		log.Printf("WireWall %s: http://%s; operatör anahtarı %s", backend, listen, filepath.Join(data, "operator.token"))
	}
	if backend == "lab" {
		log.Print("LABORATUVAR: sentetik veri; gerçek trafik gönderilmez ve host korunmaz")
	}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// A bootstrap file must not silently discard edits saved through the panel.
func startupPolicy(store *control.Store, path string, replace bool, iface, mode string) (*model.Policy, error) {
	stored, _, exists, err := store.Load()
	if err != nil {
		return nil, err
	}
	if replace && path == "" {
		return nil, errors.New("--replace-policy için --policy gerekli")
	}
	var p model.Policy
	if exists && !replace {
		p = stored
		if iface == "" && mode == "" {
			return nil, nil
		}
	} else if path != "" {
		p, err = readPolicy(path)
		if err != nil {
			return nil, err
		}
	} else {
		p = policy.Default()
	}
	changed := false
	if iface != "" && iface != p.Interface {
		p.Interface = iface
		changed = true
	}
	if mode != "" && mode != p.XDPMode {
		p.XDPMode = mode
		changed = true
	}
	if exists && (replace || changed) {
		p.Version = stored.Version + 1
	}
	if err = policy.Validate(p); err != nil {
		return nil, err
	}
	return &p, nil
}

func agent(args []string) error {
	f := flag.NewFlagSet("agent", flag.ContinueOnError)
	socket := f.String("socket", "/run/wirewall/control.sock", "control Unix socket")
	data := f.String("data", "/var/lib/wirewall", "private state directory")
	path := f.String("policy", "", "bootstrap policy JSON")
	object := f.String("object", "bpf/wirewall_bpfel.o", "compiled XDP object")
	confirm := f.Bool("confirm-network-changes", false, "enable real Linux network changes")
	replace := f.Bool("replace-policy", false, "replace persisted policy with --policy")
	resume := f.Bool("resume-confirmed", false, "resume only identical previously operator-confirmed deployment")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *path == "" || !*confirm {
		return errors.New("agent --policy ve --confirm-network-changes gerektirir")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ownership, err := control.AcquireNetworkOwnership(*data)
	if err != nil {
		return err
	}
	defer ownership.Close()
	store, err := control.OpenStore(*data)
	if err != nil {
		return err
	}
	defer store.Close()
	initial, err := startupPolicy(store, *path, *replace, "", "")
	if err != nil {
		return err
	}
	service, err := control.NewService(store, initial, "xdp")
	if err != nil {
		return err
	}
	defer service.Close()
	live, err := control.NewXDPRuntime(ctx, service.Policy(), service.Bans(), *object, *data, ownership, *resume)
	if err != nil {
		return err
	}
	service.SetRuntime(live)
	done := make(chan struct{})
	go func() { defer close(done); service.Run(ctx) }()
	defer func() { cancel(); <-done }()
	log.Printf("WireWall privileged agent: %s; TCP listener yok", *socket)
	return control.ServeAgent(ctx, *socket, service)
}
