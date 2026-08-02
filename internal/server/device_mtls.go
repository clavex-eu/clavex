package server

// Device CA renewal listener.
//
// This is a SEPARATE *http.Server/port from the main API listener because the
// main listener's TLS config (crypto.BuildServerTLSConfig) is either fully
// optional client-cert (RFC 8705 certificate-bound tokens) or a single
// static, file-based CA (MTLSClientCACertFile) — neither fits a renewal
// endpoint that must REQUIRE a valid client cert and verify it against a
// dynamically-changing, per-tenant set of Device CA certificates (one org
// onboarding, or one CA rotation, must not require restarting the whole
// server). The pool is rebuilt from the database on a short interval and
// swapped atomically via tls.Config.GetConfigForClient.
//
// Accepting a handshake against this listener's (necessarily unioned, every
// tenant's CA) pool only proves "signed by SOME org's Device CA" — the
// handler (DeviceRenewHandler.Renew) re-verifies the SPECIFIC tenant named in
// the presented certificate's own CN before trusting it for anything.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/clavex-eu/clavex/internal/devicepki"
	"github.com/clavex-eu/clavex/internal/handler"
	"github.com/clavex-eu/clavex/internal/repository"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

// deviceMTLSPoolRefreshInterval bounds how long a newly onboarded org (or a
// completed CA rotation) takes to become renewal-capable on this listener.
const deviceMTLSPoolRefreshInterval = 5 * time.Minute

func (s *Server) startDeviceMTLSListener(ctx context.Context) error {
	addr := s.cfg.HTTP.DeviceMTLSAddr
	if addr == "" {
		return nil // feature disabled
	}
	if s.cfg.HTTP.TLSCertFile == "" || s.cfg.HTTP.TLSKeyFile == "" {
		return fmt.Errorf("device_mtls_addr is set but tls_cert_file/tls_key_file are not — the renewal listener needs a server certificate")
	}
	serverCert, err := tls.LoadX509KeyPair(s.cfg.HTTP.TLSCertFile, s.cfg.HTTP.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("load server certificate: %w", err)
	}

	repo := repository.NewDevicePKIRepository(s.pool)
	svc := devicepki.NewService(repo, s.enc, s.webhookDisp)

	var current atomic.Pointer[tls.Config]
	refresh := func() {
		pool, err := svc.BuildClientCAPool(ctx)
		if err != nil {
			log.Error().Err(err).Msg("device-mtls: refresh client CA pool")
			return
		}
		current.Store(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			MinVersion:   tls.VersionTLS12,
		})
	}
	refresh()

	go func() {
		ticker := time.NewTicker(deviceMTLSPoolRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	renewH := handler.NewDeviceRenewHandler(s.pool, s.enc, s.webhookDisp)
	e.POST("/renew", renewH.Renew)

	srv := &http.Server{
		Addr:    addr,
		Handler: e,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return current.Load(), nil
			},
		},
	}
	s.deviceMTLSSrv = srv

	go func() {
		log.Info().Str("addr", addr).Msg("device-mtls: listening")
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("device-mtls: listener stopped")
		}
	}()
	return nil
}
