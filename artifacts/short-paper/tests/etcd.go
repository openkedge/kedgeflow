package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
)

func freeURL() url.URL {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { panic(err) }
	addr := l.Addr().String()
	_ = l.Close()
	u, err := url.Parse("http://" + addr)
	if err != nil { panic(err) }
	return *u
}

func main() {
	dir, err := os.MkdirTemp("/private/tmp", "kedgeflow-rust-etcd36-")
	if err != nil { panic(err) }
	peers, clients := make([]url.URL, 3), make([]url.URL, 3)
	parts := make([]string, 3)
	for i := 0; i < 3; i++ {
		peers[i], clients[i] = freeURL(), freeURL()
		parts[i] = fmt.Sprintf("node%d=%s", i, peers[i].String())
	}
	servers := make([]*embed.Etcd, 0, 3)
	defer func() {
		for _, server := range servers { server.Close() }
		_ = os.RemoveAll(dir)
	}()
	for i := 0; i < 3; i++ {
		cfg := embed.NewConfig()
		cfg.Name = fmt.Sprintf("node%d", i)
		cfg.Dir = fmt.Sprintf("%s/node%d", dir, i)
		cfg.ListenPeerUrls = []url.URL{peers[i]}
		cfg.AdvertisePeerUrls = cfg.ListenPeerUrls
		cfg.ListenClientUrls = []url.URL{clients[i]}
		cfg.AdvertiseClientUrls = cfg.ListenClientUrls
		cfg.InitialCluster = strings.Join(parts, ",")
		cfg.InitialClusterToken = "kedgeflow-rust-tests"
		cfg.EnableGRPCGateway = true
		cfg.LogLevel = "error"
		cfg.LogOutputs = []string{"stderr"}
		cfg.TickMs, cfg.ElectionMs = 100, 1000
		server, startErr := embed.StartEtcd(cfg)
		if startErr != nil { panic(startErr) }
		servers = append(servers, server)
	}
	for _, server := range servers {
		select {
		case <-server.Server.ReadyNotify():
		case <-time.After(30 * time.Second): panic("etcd cluster timeout")
		}
	}
	endpoints := make([]string, 3)
	for i := range clients { endpoints[i] = clients[i].String() }
	data, err := json.Marshal(endpoints)
	if err != nil { panic(err) }
	if err := os.WriteFile(os.Args[1], data, 0600); err != nil { panic(err) }
	fmt.Printf("READY members=3 endpoints=%s\n", data)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
