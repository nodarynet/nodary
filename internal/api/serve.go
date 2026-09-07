package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Serve runs the control plane until the context is cancelled.
//
// TLS always. There is no plaintext mode and no flag for one: the node protocol
// carries client certificates and the operator surface carries session cookies
// and bearer tokens, and an option to serve those in the clear is an option
// somebody enables to debug something and forgets.
func (s *Server) Serve(ctx context.Context, c ServerConfig) error {
	if c.TLS.Certificate == "" || c.TLS.Key == "" {
		return fmt.Errorf("%w: no TLS certificate; run `nodary server install` to generate one", ErrBadServerConfig)
	}
	cert, err := tls.LoadX509KeyPair(c.TLS.Certificate, c.TLS.Key)
	if err != nil {
		return fmt.Errorf("loading the TLS certificate: %w", err)
	}
	cfg, err := s.TLSConfig()
	if err != nil {
		return err
	}
	cfg.Certificates = []tls.Certificate{cert}

	srv := &http.Server{
		Handler:           s.Handler(),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", c.Bind)
	if err != nil {
		return fmt.Errorf("binding %s: %w", c.Bind, err)
	}

	done := make(chan error, 1)
	go func() {
		err := srv.ServeTLS(ln, "", "")
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// A bounded shutdown: an in-flight mutation should finish, and a
		// long-poll should not hold the process open forever.
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	}
}

// TLSConfig is the listener's configuration without a server certificate, so
// that Serve and a test that wants a real mTLS listener share one definition of
// how a client certificate is treated rather than two that can drift.
func (s *Server) TLSConfig() (*tls.Config, error) {
	pool, err := s.agentCAPool()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		// 1.2 is the floor rather than 1.3 because an agent or an operator on an
		// older userland still has to reach the control plane, and the approved
		// cipher suites are the same either way.
		MinVersion: tls.VersionTLS12,
		// One listener serves operators and agents, so a client certificate is
		// verified when offered and never demanded: an operator with a session
		// cookie has none, and RequireAndVerifyClientCert would close the
		// connection before they could present it.
		//
		// "If given" is not a weakening. The agent endpoints require a verified
		// chain themselves (agentNode), and a certificate that arrives
		// unverifiable fails the handshake here rather than reaching a handler
		// that might trust its common name.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
	}, nil
}

// agentCAPool is what a client certificate is verified against.
//
// A missing agent CA is fatal rather than "serve without mTLS": the fallback
// would be a control plane that starts happily and refuses every node, which is
// a failure discovered on a GPU host by somebody who cannot see this log line.
func (s *Server) agentCAPool() (*x509.CertPool, error) {
	if s.pki == "" {
		return nil, fmt.Errorf("%w: no PKI directory; run `nodary server install`", ErrBadServerConfig)
	}
	pem, err := os.ReadFile(AgentCAPath(s.pki))
	if err != nil {
		return nil, fmt.Errorf("reading the agent CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%w: %s holds no usable certificate", ErrBadServerConfig, AgentCAPath(s.pki))
	}
	return pool, nil
}
