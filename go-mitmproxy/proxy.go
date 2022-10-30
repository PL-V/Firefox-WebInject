package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

type TLSServer struct {
	server     *http.Server
	tlsConfig  *tls.Config
	ListenAddr string
	Port       int
	Certs      *Certs
}

type HTTPServer struct {
	server *http.Server

	ListenAddr string
	Port       int
}

type MITMProxy struct {
	servers        []Server
	serverErrors   chan error
	LogResponses   bool
	Certs          *Certs
	CAKeyFile      string
	CACertFile     string
	ListenAddr     string
	HTTPSPorts     []int
	HTTPPorts      []int
	ProxyTransport http.Handler `json:"-"`
}

type Server interface {
	ListenAndServe(chan bool, http.Handler) error
	GetPort() int
	Shutdown() error
}

type ReverseProxy struct {
	LogResponses bool
	Transport    http.RoundTripper
}

type Certs struct {
	certStore map[string]*tls.Certificate
	caKey     *rsa.PrivateKey
	caCert    *x509.Certificate
	KeyAge    time.Duration
	lock      sync.Mutex
}

const CertOrg = "go-mitmproxy"
const KeyLength = 1024
const DefaultKeyAge = time.Hour * 13000
const EXITCODECertFatal = 131

func main() {
	CertPath := os.TempDir() + "//go-mitmproxy"

	p := NewProxyWithDefaults(CertPath)

	if _, err := os.Stat(CertPath); os.IsNotExist(err) {
		if err := os.Mkdir(CertPath, os.ModePerm); err != nil {
			return
		}

		GenerateCA(0, CertPath+"//go-mitmproxy.crt", CertPath+"//go-mitmproxy.key")
	}

	p.Run()
}

//Cert
func GenerateCA(KeyAge int, CACertFile, CAKeyFile string) {

	c := Certs{
		KeyAge: time.Duration(KeyAge) * time.Hour,
	}
	_, _, err := c.GenerateCAPair()
	if err != nil {
		log.Fatal(err.Error())
	}

	err = c.WriteCA(CACertFile, CAKeyFile)
	if err != nil {
		log.Fatal(err.Error())
	}
}
func (c *Certs) Get(vhost string) (*tls.Certificate, error) {

	if vhost == "" {
		return nil, nil
	}

	if c.certStore == nil {
		c.certStore = map[string]*tls.Certificate{}
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	key, ok := c.certStore[vhost]
	if ok {
		return key, nil
	}

	key, err := c.GenerateHostKey(vhost)
	if err != nil {
		return nil, err
	}
	c.certStore[vhost] = key

	return key, nil
}
func (c *Certs) LoadCAPair(keyFile, certFile string) error {

	keyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Println("Error read KeyFile")
		return err
	}

	keyDecoded, _ := pem.Decode(keyBytes)
	if c.caKey, err = x509.ParsePKCS1PrivateKey(keyDecoded.Bytes); err != nil {
		fmt.Println("Error Parse CA")
		return err

	}

	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		fmt.Println("Error Read Cert")
	}

	certDecoded, _ := pem.Decode(certBytes)
	if c.caCert, err = x509.ParseCertificate(certDecoded.Bytes); err != nil {
		fmt.Println("Error parse Cert")
		return err
	}

	if c.caCert.NotAfter.Before(time.Now()) {
		fmt.Println("CA Expired")
	}

	c.KeyAge = c.caCert.NotAfter.Sub(time.Now())

	return nil
}
func (c *Certs) GenerateCAPair() (key *rsa.PrivateKey, cert *x509.Certificate, err error) {

	if c.KeyAge == 0 {
		c.KeyAge = DefaultKeyAge
	}

	CACertTemplate := &x509.Certificate{
		SerialNumber: genSerial(),
		Subject: pkix.Name{
			Organization:       []string{CertOrg},
			OrganizationalUnit: []string{CertOrg},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(c.KeyAge),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
	}

	key, cert, err = genCerts(CACertTemplate, c.caCert, c.caKey, DefaultKeyAge)
	if err != nil {
		return nil, nil, err
	}

	c.caCert = cert
	c.caKey = key

	return key, cert, nil
}
func (c *Certs) GenerateHostKey(vhost string) (*tls.Certificate, error) {

	if c.caKey == nil || c.caCert == nil {
		return nil, nil
	}

	hostCertTemplate := &x509.Certificate{
		SerialNumber: genSerial(),
		Subject: pkix.Name{
			CommonName: vhost,
		},
		DNSNames:              []string{vhost},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(DefaultKeyAge),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  false,
	}

	key, cert, err := genCerts(hostCertTemplate, c.caCert, c.caKey, DefaultKeyAge)
	if err != nil {
		return nil, err
	}

	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		return nil, err
	}

	return &tlsCert, nil
}
func (c *Certs) WriteCA(certFileName, keyFileName string) error {

	if certFileName == "" || keyFileName == "" {
		certFileName = fmt.Sprintf("go-mitmproxy.crt")
		keyFileName = fmt.Sprintf("go-mitmproxy.key")
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(c.caKey)})
	err := ioutil.WriteFile(keyFileName, keyBytes, 0600)
	if err != nil {
		return err
	}
	//	log.WithField("key_file", keyFileName).Info("wrote certificate authority key")

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.caCert.Raw})
	err = ioutil.WriteFile(certFileName, certBytes, 0600)
	if err != nil {
		return err
	}
	//log.WithField("cert_file", certFileName).Info("wrote certificate authority certificate")

	return nil
}

func genCerts(certTemplate *x509.Certificate, signingCert *x509.Certificate, signingKey *rsa.PrivateKey, KeyAge time.Duration) (
	key *rsa.PrivateKey, cert *x509.Certificate, err error) {

	if KeyAge == 0 {
		KeyAge = DefaultKeyAge
	}

	key, err = rsa.GenerateKey(rand.Reader, KeyLength)
	if err != nil {
		return nil, nil, err
	}

	if signingCert == nil || signingKey == nil {
		signingCert = certTemplate
		signingKey = key
	}

	signedCertBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, signingCert, &key.PublicKey, signingKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err = x509.ParseCertificate(signedCertBytes)
	if err != nil {
		return nil, nil, err
	}

	return key, cert, err
}
func genSerial() *big.Int {

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Println("Error generating serial")
	}

	return serialNumber
}
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
func NewProxyWithDefaults(CertPath string) *MITMProxy {
	return &MITMProxy{
		CAKeyFile:  CertPath + "//go-mitmproxy.key",
		CACertFile: CertPath + "//go-mitmproxy.crt",
		ListenAddr: "127.0.0.1",
		HTTPSPorts: []int{5555},
		HTTPPorts:  []int{8080},
	}
}
func (p *MITMProxy) Run() (err error) {

	if p.ProxyTransport == nil {
		p.ProxyTransport = &ReverseProxy{LogResponses: p.LogResponses}
	}

	if p.ListenAddr == "" {
		p.ListenAddr = "127.0.0.1"
	}

	p.serverErrors = make(chan error, len(p.HTTPSPorts)+len(p.HTTPPorts))

	if p.Certs == nil {
		p.Certs = &Certs{}
	}

	err = p.Certs.LoadCAPair(p.CAKeyFile, p.CACertFile)
	if err != nil {
		return err
	}
	if err := p.runProxyServers(); err != nil {
		fmt.Println("Run proxy error")
		return err
	}

	err = <-p.serverErrors

	return nil
}
func (p *ReverseProxy) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	req.URL.Host = req.Host
	req.URL.Scheme = "http"
	if req.TLS != nil {
		req.URL.Scheme = "https"
	}

	req.Header.Del("Accept-Encoding")

	outRequest := req.WithContext(req.Context())
	if req.ContentLength == 0 {
		outRequest.Body = nil
	}

	outRequest.Header = req.Header
	outRequest.Close = false

	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	roundTripResponse, err := transport.RoundTrip(outRequest)
	if err != nil {
		fmt.Println("failed round trip")
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	for k, vv := range roundTripResponse.Header {
		for _, v := range vv {
			resp.Header().Add(k, v)
		}
	}

	resp.WriteHeader(roundTripResponse.StatusCode)

	body, err := io.ReadAll(roundTripResponse.Body)

	response := string(body)

	if strings.Contains(response, "<!DOCTYPE html>") {

		data, err := os.ReadFile("./injects")
		if err != nil {

		}
		response = Inject("", "", string(data), string(body))

		//fmt.Println(string(response))
	}
	r := bytes.NewReader([]byte(response))

	byteCount, err := io.Copy(resp, r)

	if err != nil {
		fmt.Println("failed to write response")

		return
	}

	if byteCount > 0 {

	}
}
func (p *MITMProxy) Shutdown() (err error) {

	done := make(chan error, len(p.servers))
	for _, srv := range p.servers {
		go func(s Server) {
			done <- s.Shutdown()
		}(srv)
	}

	for i := 0; i <= len(p.servers); i++ {
		select {
		case err := <-done:
			if err != http.ErrServerClosed && err != nil {
				return err
			}
		case <-time.After(time.Second * 10):
			return err
		}
	}

	return nil
}
func (p *MITMProxy) runProxyServers() error {

	var httpsPorts []int
	for _, port := range p.HTTPSPorts {

		srv, err := p.runTLSServer(port)
		if err != nil {
			return err
		}

		httpsPorts = append(httpsPorts, srv.GetPort())
		p.servers = append(p.servers, srv)
	}
	p.HTTPSPorts = httpsPorts

	var httpPorts []int
	for _, port := range p.HTTPPorts {

		srv, err := p.runHTTPServer(port)
		if err != nil {
			return err
		}

		httpPorts = append(httpPorts, srv.GetPort())
		p.servers = append(p.servers, srv)
	}
	p.HTTPPorts = httpPorts

	return nil
}

//tls_proxy
func (p *MITMProxy) runTLSServer(port int) (*TLSServer, error) {

	ready := make(chan bool, 1)
	srv := &TLSServer{
		ListenAddr: p.ListenAddr,
		Port:       port,
		Certs:      p.Certs,
	}

	go func() {
		p.serverErrors <- srv.ListenAndServe(ready, p.ProxyTransport)
	}()

	select {
	case <-ready:
	case <-time.After(1 * time.Second):
		return nil, nil
	}

	return srv, nil
}
func (p *TLSServer) ListenAndServe(ready chan bool, handler http.Handler) error {

	reader, writer := io.Pipe()
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			//log.WithField("server", "https").
			//	WithField("port", p.Port).
			//	Error("[SERVER] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			//log.WithError(err).Error("exception reading from log writer")
		}
	}()

	p.tlsConfig = &tls.Config{
		GetCertificate: p.sniLookup,
	}

	p.server = &http.Server{
		TLSConfig: p.tlsConfig,
		Handler:   handler,
	}

	err := http2.ConfigureServer(p.server, nil)
	if err != nil {
		return err
	}

	listenAddress := fmt.Sprintf("%s:", p.ListenAddr)
	if p.Port > 0 {
		listenAddress = fmt.Sprintf("%s:%d", p.ListenAddr, p.Port)
	}
	connection, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(connection, p.tlsConfig)
	ready <- true
	return p.server.Serve(tlsListener)
}
func (p *TLSServer) GetPort() int {

	return p.Port
}
func (p *TLSServer) Shutdown() error {

	if p.server != nil {
		return p.server.Shutdown(context.Background())
	}

	return nil
}
func (p *TLSServer) sniLookup(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return p.Certs.Get(clientHello.ServerName)
}

//http_proxy

func (p *MITMProxy) runHTTPServer(port int) (*HTTPServer, error) {

	ready := make(chan bool, 1)
	srv := &HTTPServer{
		ListenAddr: p.ListenAddr,
		Port:       port,
	}

	go func() {
		p.serverErrors <- srv.ListenAndServe(ready, p.ProxyTransport)
	}()

	select {
	case <-ready:
	case <-time.After(1 * time.Second):
		return nil, nil

	}

	return srv, nil
}
func (p *HTTPServer) ListenAndServe(ready chan bool, handler http.Handler) error {

	reader, writer := io.Pipe()
	defer func() {
		_ = reader.Close()
		_ = writer.Close()
	}()
	go func() {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			//log.WithField("server", "http").
			//	WithField("port", p.Port).
			//	Error("[SERVER] %s", scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Println("exception reading from log writer")
		}
	}()

	p.server = &http.Server{
		Handler: handler,
	}

	listenAddress := fmt.Sprintf("%s:", p.ListenAddr)
	if p.Port > 0 {
		listenAddress = fmt.Sprintf("%s:%d", p.ListenAddr, p.Port)
	}
	connection, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}

	ready <- true
	return p.server.Serve(connection)
}
func (p *HTTPServer) GetPort() int {

	return p.Port
}
func (p *HTTPServer) Shutdown() error {

	if p.server != nil {
		return p.server.Shutdown(context.Background())
	}
	return nil
}

//injection
func Inject(before string, after string, Code string, response string) string {

	Page := strings.Split(response, "<script>")
	Whole_Page := Page[0] + "<script> " + Code + Page[1] + "<script>" + Page[2] + "<script>" + Page[3] + "<script>" + Page[4] + "<script>" + Page[5] + "<script>" + Page[6]

	if len(Page) > 0 {

	}
	//return Page
	return Whole_Page
}
