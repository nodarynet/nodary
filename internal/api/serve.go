package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Serve runs the control plane until the context is cancelled.
//
// TLS always. There is no plaintext mode and no flag for one: the node protocol
// carries client certificates and the operator surface carries session cookies
// and bearer tokens, and an option to serve those in the clear is an option
// somebody enables to debug something and forgets.
func Serve(ctx context.Context, h http.Handler, c ServerConfig) error {
	if c.TLS.Certificate == "" || c.TLS.Key == "" {
		return fmt.Errorf("%w: no TLS certificate; run `nodary server install` to generate one", ErrBadServerConfig)
	}
	cert, err := tls.LoadX509KeyPair(c.TLS.Certificate, c.TLS.Key)
	if err != nil {
		return fmt.Errorf("loading the TLS certificate: %w", err)
	}

	srv := &http.Server{
		Handler: h,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			// 1.2 is the floor rather than 1.3 because an agent or an operator
			// on an older userland still has to reach the control plane, and
			// the cipher suites below are the approved ones either way.
			MinVersion: tls.VersionTLS12,
		},
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
