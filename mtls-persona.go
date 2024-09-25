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
	Address_Pairs []address_pair `json:"Address_Pairs"`
	Client_Cert   string         `json:"Client_Cert"`
	Client_Key    string         `json:"Client_Key"`
	CA_Cert       string         `json:"CA_Cert"`
	auto_reload   bool            `json:"auto_reload"`
}

type address_pair struct {
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

var (
	tls_config    *tls.Config
	cfg           *config
	mu            sync.Mutex
	tls_config_mu sync.RWMutex
	last_cert_info  certInfo // Struct to track certificate file modification time
	active_connections   = struct {
		sync.RWMutex
		connections []net.Conn // Track active outbound connections
	}{}
)

type certInfo struct {
	Client_Cert_Mod_Time time.Time
	Client_Key_Mod_Time  time.Time
	CA_Cert_Mod_Time     time.Time
}

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
	for _, pair := range cfg.Address_Pairs {
		go start_listener(pair.Inbound, pair.Outbound)
	}

	// Schedule certificate reload
	if cfg.auto_reload == true { 
		go func() {
			for {
				now := time.Now()
				next_reload := now.Add(1 * time.Minute)
				time.Sleep(time.Until(next_reload))
				if err := reload_certificates(); err != nil {
					log.Printf("Failed to reload certificates: %v", err)
				}
			}
		}()
	} else {
		log.Printf("Certificate auto-reload disabled. Application needs restart to pick up rotated cerfificate.\n")
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

func reload_certificates() error {
	mu.Lock()
	defer mu.Unlock()

	// Check if the client certificate has changed
	Client_CertChanged, Client_Cert_Mod_Time, err := file_has_changed(cfg.Client_Cert, last_cert_info.Client_Cert_Mod_Time)
	if err != nil {
		return fmt.Errorf("failed to check client certificate: %v", err)
	}

	// Check if the client key has changed
	Client_KeyChanged, Client_Key_Mod_Time, err := file_has_changed(cfg.Client_Key, last_cert_info.Client_Key_Mod_Time)
	if err != nil {
		return fmt.Errorf("failed to check client key: %v", err)
	}

	// Check if the CA certificate has changed
	CA_CertChanged, CA_Cert_Mod_Time, err := file_has_changed(cfg.CA_Cert, last_cert_info.CA_Cert_Mod_Time)
	if err != nil {
		return fmt.Errorf("failed to check CA certificate: %v", err)
	}

	// If no files have changed, skip reloading
	if !Client_CertChanged && !Client_KeyChanged && !CA_CertChanged {
		log.Println("No certificate changes detected; skipping reload.")
		return nil
	}

	// Reload the certificates
	log.Printf("Reloading certificates from files:\n        Cert File=%s, \n        Key File=%s, \n        CA File=%s", cfg.Client_Cert, cfg.Client_Key, cfg.CA_Cert)

	// Load the client certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.Client_Cert, cfg.Client_Key)
	if err != nil {
		return fmt.Errorf("failed to load client certificate and key: %v", err)
	}

	// ----- print certificate details ------------
	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("Failed to parse certificate: %v\n", err)
	}

	// Print certificate details
	fmt.Printf("        Subject: %s\n", parsedCert.Subject)
	fmt.Printf("        Serial Number: %s\n", parsedCert.SerialNumber.String())
	fmt.Printf("        Not Before: %s\n", parsedCert.NotBefore)
	fmt.Printf("        Not After: %s\n------------------------\n", parsedCert.NotAfter)
	// -------------------

	// Load the CA certificate
	CA_Cert_pool := x509.NewCertPool()
	CA_Cert_bytes, err := ioutil.ReadFile(cfg.CA_Cert)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}
	if ok := CA_Cert_pool.AppendCertsFromPEM(CA_Cert_bytes); !ok {
		return fmt.Errorf("failed to append CA certificate to pool")
	}

	// Update the TLS configuration
	new_tls_config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            CA_Cert_pool,
		InsecureSkipVerify: true, // Use this only for testing; remove in production!
	}

	// Safely update the TLS configuration
	tls_config_mu.Lock()
	tls_config = new_tls_config
	tls_config_mu.Unlock()

	// Close all active outbound connections after reloading certificates
	close_active_connections()

	// Update last modification times
	last_cert_info.Client_Cert_Mod_Time = Client_Cert_Mod_Time
	last_cert_info.Client_Key_Mod_Time = Client_Key_Mod_Time
	last_cert_info.CA_Cert_Mod_Time = CA_Cert_Mod_Time

	log.Println("Certificates reloaded successfully and outbound connections closed.")

	return nil
}

// Close all active outbound connections
func close_active_connections() {
	active_connections.Lock()
	defer active_connections.Unlock()

	log.Println("Closing all active outbound connections")
	for _, conn := range active_connections.connections {
		conn.Close()
	}
	// Clear the list of active connections
	active_connections.connections = nil
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

	for {
		outbound_conn, err := get_outbound_conn(outbound_addr)
		if err != nil {
			log.Printf("Failed to get outbound connection to %s: %v", outbound_addr, err)
			time.Sleep(2 * time.Second) // Retry after 2 seconds if failed
			continue
		}

		defer outbound_conn.Close()

		log.Printf("Forwarding traffic between %s (inbound: %s) and %s (outbound)", inbound_conn.RemoteAddr(), inbound_addr, outbound_addr)

		// Channel to signal when either side of the connection closes
		done := make(chan struct{})

		go func() {
			copy_data(outbound_conn, inbound_conn, done)
		}()
		go func() {
			copy_data(inbound_conn, outbound_conn, done)
		}()

		// Wait for either direction to close and handle reconnect if needed
		select {
		case <-done:
			log.Printf("Connection closed, closing inbound connection and retrying outbound connection to %s", outbound_addr)
			inbound_conn.Close() // Close inbound connection
			outbound_conn.Close() // Ensure outbound connection is closed
			return
		}
	}
}

func get_outbound_conn(outbound_addr string) (net.Conn, error) {
	tls_config_mu.RLock()
	defer tls_config_mu.RUnlock()

	conn, err := tls.Dial("tcp", outbound_addr, tls_config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to outbound address %s: %v", outbound_addr, err)
	}

	// Add the connection to the list of active connections
	active_connections.Lock()
	active_connections.connections = append(active_connections.connections, conn)
	active_connections.Unlock()

	if tcp_conn, ok := conn.NetConn().(*net.TCPConn); ok {
		tcp_conn.SetKeepAlive(true)
		tcp_conn.SetKeepAlivePeriod(5 * time.Minute)
	}

	return conn, nil
}

func copy_data(dst net.Conn, src net.Conn, done chan struct{}) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("Error copying data: %v", err)
	}
	// Signal that copying is done (either an error occurred or the connection was closed)
	done <- struct{}{}
}
