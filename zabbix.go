// Package implement zabbix sender protocol for send metrics to zabbix.
package zabbix

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"path/filepath"
	"time"
)

var (
	errPathNotAbsolute = errors.New(
		"path must be absolute",
	)
)

const defaultConnectionTimeout = 5 * time.Second

// Metric struct.
type Metric struct {
	Host  string `json:"host"`
	Key   string `json:"key"`
	Value string `json:"value"`
	Clock int64  `json:"clock"`
}

func NewMetric(host, key, value string, clock ...int64) *Metric {
	m := &Metric{
		Host:  host,
		Key:   key,
		Value: value,
		Clock: time.Now().Unix(),
	}

	if len(clock) > 0 {
		m.Clock = clock[0]
	}

	return m
}

// Packet struct.
type Packet struct {
	Request string    `json:"request"`
	Data    []*Metric `json:"data"`
	Clock   int64     `json:"clock"`
}

func NewPacket(data []*Metric, clock ...int64) *Packet {
	p := &Packet{
		Request: `sender data`,
		Data:    data,
		Clock:   time.Now().Unix(),
	}

	if len(clock) > 0 {
		p.Clock = clock[0]
	}

	return p
}

// DataLen Packet class method, return 8 bytes with packet length in little endian order.
func (p *Packet) DataLen() []byte {
	dataLen := make([]byte, 8)
	JSONData, _ := json.Marshal(p)
	binary.LittleEndian.PutUint32(dataLen, uint32(len(JSONData)))

	return dataLen
}

// Sender struct.
type Sender struct {
	Host              string
	Port              int
	tlsConfig         *tls.Config
	connectionTimeout time.Duration
}

// Sender constructor.
func NewSender(host string, port int) *Sender {
	return &Sender{
		Host:              host,
		Port:              port,
		tlsConfig:         nil,
		connectionTimeout: defaultConnectionTimeout,
	}
}

func (s *Sender) EnableTLS(
	certificate string,
	privateKey string,
	ca string,
) error {
	pool, err := s.getTLSCARootPool(ca)
	if err != nil {
		return fmt.Errorf("can't get certs pool, reason: %w", err)
	}

	if certificate == "" || privateKey == "" {
		return errors.New("certificate and key paths can't be empty")
	}

	if !filepath.IsAbs(certificate) || !filepath.IsAbs(privateKey) {
		return fmt.Errorf(
			"can't use certificate or private key reason: %w",
			errPathNotAbsolute,
		)
	}

	keypair, err := tls.LoadX509KeyPair(certificate, privateKey)
	if err != nil {
		return fmt.Errorf(
			"can't load certificate and key as x509 keypair, reason: %w",
			err,
		)
	}

	s.tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{keypair},
		RootCAs:            pool,
		InsecureSkipVerify: true,
	}

	return nil
}

func (s Sender) getTLSCARootPool(
	ca string,
) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("can't init system certs pool, reason: %w", err)
	}

	if ca != "" {
		if !filepath.IsAbs(ca) {
			return nil, fmt.Errorf(
				"can't use CA certificate, reason: %w", errPathNotAbsolute,
			)
		}

		ca, err := ioutil.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf(
				"can't read CA file path %s, reason: %w", ca, err,
			)
		}

		pool = x509.NewCertPool()

		ok := pool.AppendCertsFromPEM(ca)
		if !ok {
			return nil, errors.New("unable to append CA to certificate pool")
		}
	}

	return pool, nil
}

func (s *Sender) WithConnectionTimeout(
	timeout time.Duration,
) *Sender {
	s.connectionTimeout = timeout

	return s
}

// Method Sender class, return zabbix header.
func (s *Sender) getHeader() []byte {
	return []byte("ZBXD\x01")
}

// Method Sender class, resolve uri by name:port.
func (s *Sender) getTCPAddr() (iaddr *net.TCPAddr, err error) {
	// format: hostname:port
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)

	// Resolve hostname:port to ip:port
	iaddr, err = net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		err = fmt.Errorf("connection failed: %w", err)

		return
	}

	return
}

// Method Sender class, make connection to uri.
func (s *Sender) connect() (conn net.Conn, err error) {
	iaddr, err := s.getTCPAddr()
	if err != nil {
		return
	}

	var dialer net.Dialer

	ctx, cancel := context.WithTimeout(
		context.Background(), s.connectionTimeout,
	)
	defer cancel()

	if s.tlsConfig != nil {
		tlsDialer := tls.Dialer{
			NetDialer: &dialer,
			Config:    s.tlsConfig,
		}

		conn, err = tlsDialer.DialContext(ctx, "tcp", iaddr.String())
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", iaddr.String())
	}

	return
}

// Method Sender class, read data from connection.
func (s *Sender) read(reader io.Reader) (res []byte, err error) {
	res = make([]byte, 1024)

	res, err = ioutil.ReadAll(reader)
	if err != nil {
		err = fmt.Errorf("error while receiving the data: %w", err)

		return
	}

	return
}

// Method Sender class, send packet to zabbix.
func (s *Sender) Send(packet *Packet) (res []byte, err error) {
	conn, err := s.connect()
	if err != nil {
		return
	}
	defer conn.Close()

	dataPacket, _ := json.Marshal(packet)

	buffer := append(s.getHeader(), packet.DataLen()...)
	buffer = append(buffer, dataPacket...)

	_, err = conn.Write(buffer)
	if err != nil {
		err = fmt.Errorf("error while sending the data: %w", err)

		return
	}

	res, err = s.read(conn)

	return
}
