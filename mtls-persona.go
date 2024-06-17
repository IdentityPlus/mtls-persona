package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type config struct {
	AddressPairs []address_pair `json:"address_pairs"`
	ClientCert   string         `json:"client_cert"`
	ClientKey    string         `json:"client_key"`
	CaCert       string         `json:"ca_cert"`
	ReloadHour   int            `json:"reload_hour"`
}

type address_pair struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

var (
	tls_config   *tls.Config
	cfg          *config
	mu           sync.Mutex
	tls_config_mu sync.RWMutex
)

func main() {
	// Load initial configuration from file
	var err error
	cfg, err = load_config("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Log the configuration for debugging
	log.Printf("Loaded configuration: %+v", cfg)

	// Load initial certificates
	if err := reload_certificates(); err != nil {
		log.Fatalf("Failed to load initial certificates: %v", err)
	}

	// Start listening for inbound connections on multiple addresses
	for _, pair := range cfg.AddressPairs {
		go start_listener(pair.Inbound, pair.Outbound)
	}

	// Schedule certificate reload at the specified hour each day
	go func() {
		for {
			now := time.Now()
			next_reload := time.Date(now.Year(), now.Month(), now.Day(), cfg.ReloadHour, 0, 0, 0, now.Location())
			if now.After(next_reload) {
				next_reload = next_reload.Add(24 * time.Hour)
			}
			time.Sleep(time.Until(next_reload))
			if err := reload_certificates(); err != nil {
				log.Printf("Failed to reload certificates: %v", err)
			} else {
				log.Printf("Certificates reloaded successfully at %v", next_reload)
			}
		}
	}()

	// Prevent the main function from exiting
	select {}
}

func load_config(filename string) (*config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	var cfg config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %v", err)
	}

	return &cfg, nil
}

func reload_certificates() error {
	mu.Lock()
	defer mu.Unlock()

	log.Printf("Reloading certificates from files: cert=%s, key=%s, ca=%s", cfg.ClientCert, cfg.ClientKey, cfg.CaCert)

	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return fmt.Errorf("failed to load client certificate and key: %v", err)
	}

	ca_cert_pool := x509.NewCertPool()
	ca_cert_bytes, err := ioutil.ReadFile(cfg.CaCert)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	if ok := ca_cert_pool.AppendCertsFromPEM(ca_cert_bytes); !ok {
		return fmt.Errorf("failed to append CA certificate to pool")
	}

	new_tls_config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            ca_cert_pool,
		InsecureSkipVerify: true, // Use this only for testing; remove in production!
	}

	tls_config_mu.Lock()
	tls_config = new_tls_config
	tls_config_mu.Unlock()

	log.Println("Certificates reloaded successfully")

	return nil
}

func start_listener(inbound_addr, outbound_addr string) {
	listener, err := net.Listen("tcp", inbound_addr)
	if err != nil {
		log.Fatalf("Failed to start listener on %s: %v", inbound_addr, err)
	}
	defer listener.Close()

	log.Printf("Listening for inbound connections on %s", inbound_addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection on %s: %v", inbound_addr, err)
			continue
		}

		log.Printf("Accepted connection on %s from %s", inbound_addr, conn.RemoteAddr())
		go handle_connection(conn, inbound_addr, outbound_addr)
	}
}

func handle_connection(inbound_conn net.Conn, inbound_addr, outbound_addr string) {
	defer inbound_conn.Close()

	outbound_conn, err := get_outbound_conn(outbound_addr)
	
	if err != nil {
		log.Printf("Failed to get outbound connection to %s: %v", outbound_addr, err)
		return
	}

	defer outbound_conn.Close()

	log.Printf("Forwarding traffic between %s (inbound: %s) and %s (outbound)", inbound_conn.RemoteAddr(), inbound_addr, outbound_addr)

	// Channel to signal when either side of the connection closes
	done := make(chan struct{})

	go func() {
		copy_data(outbound_conn, inbound_conn)
		done <- struct{}{}
	}()
	go func() {
		copy_data(inbound_conn, outbound_conn)
		done <- struct{}{}
	}()

	// Wait for both sides to finish
	<-done
	<-done
}

func get_outbound_conn(outbound_addr string) (net.Conn, error) {
	tls_config_mu.RLock()
	defer tls_config_mu.RUnlock()

	conn, err := tls.Dial("tcp", outbound_addr, tls_config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to outbound address %s: %v", outbound_addr, err)
	}
	
	if tcp_conn, ok := conn.NetConn().(*net.TCPConn); ok {
		tcp_conn.SetKeepAlive(true)
		tcp_conn.SetKeepAlivePeriod(5 * time.Minute)
	}

	return conn, nil
}

func copy_data(dst net.Conn, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("Error copying data: %v", err)
	}
}
