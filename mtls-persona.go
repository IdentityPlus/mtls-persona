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
	AddressPairs    []address_pair  `json:"address_pairs"`
	IdentityFolder  string          `json:"mtls_id_directory"`
	AgentName       string          `json:"mtls_id"`
	CaCert          string          `json:"identity_broker_ca"`
	AutoReload      bool            `json:"auto_reload"`
	Verbose		    bool			`json:"verbose"`
}

type address_pair struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}


var (
	tls_config          *tls.Config
	cfg                 *config
	mu                  sync.Mutex
	tls_config_mu       sync.RWMutex
	cert_file_time      time.Time
	active_conns   = struct {
		sync.RWMutex
		pool map[string]net.Conn
	}{}
)

func main() {
	active_conns.pool = make(map[string]net.Conn)

	// Load initial configuration from file
	var err error
	cfg, err = load_config("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Log the configuration for debugging
	log.Printf("Loaded configuration: %+v", cfg)

	// Load initial certificates
	if certificate, err := reload_certificates(); err != nil {
		log.Fatalf("Failed to load initial certificates: %v", err)
	} else {
		log.Println("Certificates loaded successfully")
		log_cert_details(certificate)
	}


	// Start listening for inbound connections on multiple addresses
	for _, pair := range cfg.AddressPairs {
		go start_listener(pair.Inbound, pair.Outbound)
	}

	// Schedule certificate reload at the specified hour each day
	if cfg.AutoReload == true {

		go func() {
			for {
				now := time.Now()
				next_reload := now.Add(1 * time.Minute)
				time.Sleep(time.Until(next_reload))

				new_cert, err := reload_certificates()

				if err != nil {
					log.Printf("Unable to reload certificates: %v", err)
				} else if new_cert != nil {
					close_active_connections();
					log.Printf("Certificates reloaded successfully at %v", next_reload)
					log_cert_details(new_cert)
				} else if cfg.Verbose {
					log.Println("No certificate changes detected; skipping reload.")
				}
				
			}
		}()

	} else {
		log.Printf("Autoreload disabled. Service needs to be restarted to pick up rotated certficates.")
	}

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

// Helper function to check if the file has changed since the last reload
func file_has_changed(filepath string, lastModTime time.Time) (bool, time.Time, error) {
	fileInfo, err := os.Stat(filepath)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("failed to stat file %s: %v", filepath, err)
	}
	// Check if the file has been modified since last time
	if fileInfo.ModTime().After(lastModTime) {
		return true, fileInfo.ModTime(), nil
	}
	return false, fileInfo.ModTime(), nil
}

func log_cert_details(cert *x509.Certificate){
	fmt.Printf("        Subject: %s\n", cert.Subject)
	fmt.Printf("        Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("        Not Before: %s\n", cert.NotBefore)
	fmt.Printf("        Not After: %s\n------------------------\n", cert.NotAfter)
}

func reload_certificates() (*x509.Certificate, error) {
	cert_changed, last_mod_time, err := file_has_changed(cfg.IdentityFolder + "/" + cfg.AgentName + ".cer", cert_file_time)

	// If no files have changed, skip reloading
	if !cert_changed {
		return nil, nil
	}

	mu.Lock()
	defer mu.Unlock()

	log.Printf("Reloading certificates from files:\n        Cert File=%s, \n        Key File=%s, \n        CA File=%s", cfg.IdentityFolder + "/" + cfg.AgentName + ".cer", cfg.IdentityFolder + "/" + cfg.AgentName + ".key", cfg.CaCert)

	cert, err := tls.LoadX509KeyPair(cfg.IdentityFolder + "/" + cfg.AgentName + ".cer", cfg.IdentityFolder + "/" + cfg.AgentName + ".key")
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %v", err)
	}
	
	// ----- print certificate details ------------
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate: %v\n", err)
	}

	ca_cert_pool := x509.NewCertPool()
	ca_cert_bytes, err := ioutil.ReadFile(cfg.CaCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}
	if ok := ca_cert_pool.AppendCertsFromPEM(ca_cert_bytes); !ok {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	new_tls_config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            ca_cert_pool,
		InsecureSkipVerify: true, // Use this only for testing; remove in production!
	}

	tls_config_mu.Lock()
	tls_config = new_tls_config
	tls_config_mu.Unlock()

	cert_file_time = last_mod_time

	return parsedCert, nil
}

func close_active_connections() {
	active_conns.Lock()
	defer active_conns.Unlock()

	log.Println("Closing all active outbound connections")
	for _, conn := range active_conns.pool {
		// will trigger cleanup and cascade the closing tot he corresponding inboud
		// see cleanup function
		conn.Close()
	}
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

		go handle_connection(conn, inbound_addr, outbound_addr)
	}
}

func handle_connection(inbound_conn net.Conn, inbound_addr, outbound_addr string) {
	defer inbound_conn.Close()

	outbound_conn, err := get_outbound_conn(inbound_addr, outbound_addr)
	
	if err != nil {
		log.Printf("Failed to get outbound connection to %s: %v", outbound_addr, err)
		return
	}

	defer outbound_conn.Close()

	if cfg.Verbose {
		log.Printf("Routing traffic between (remote: %s) -- TCP --> (inbound: %s/TCP) -- mTLS --> %s (outbound: %s/mTLS)", inbound_conn.RemoteAddr(), inbound_addr, outbound_addr)
	}

	// Channel to signal when either side of the connection closes
	done := make(chan struct{})

	go func() {
		copy_data(outbound_conn, inbound_conn)
		clean_up(inbound_conn, outbound_conn)
		done <- struct{}{}
	}()
	go func() {
		copy_data(inbound_conn, outbound_conn)
		clean_up(inbound_conn, outbound_conn)
		done <- struct{}{}
	}()

	// Wait for both sides to finish
	<-done
	<-done
}

func clean_up(inbound_conn net.Conn, outbound_conn net.Conn){
	key := outbound_conn.LocalAddr().String() + "." + outbound_conn.RemoteAddr().String()

	active_conns.Lock()

	if _, found := active_conns.pool[key]; found {
		inbound_conn.Close()
		outbound_conn.Close()
		
		if cfg.Verbose {
			log.Printf("Terminating (inbound: %s.%s/TCP) -- mTLS --> (outbound: %s.%s/mTLS)", inbound_conn.RemoteAddr(), inbound_conn.LocalAddr(), outbound_conn.LocalAddr(), outbound_conn.RemoteAddr())
		}

		delete(active_conns.pool, key)
	}

	active_conns.Unlock()
}

func get_outbound_conn(inbound_addr string, outbound_addr string) (net.Conn, error) {
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

	active_conns.Lock()
	active_conns.pool[conn.LocalAddr().String() + "." + conn.RemoteAddr().String()] = conn
	active_conns.Unlock()

	if cfg.Verbose {
		log.Printf("Monitoring outbound: %s.%s", conn.LocalAddr(), conn.RemoteAddr())
	}

	return conn, nil
}

func copy_data(dst net.Conn, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("Error copying data: %v", err)
	}
}
