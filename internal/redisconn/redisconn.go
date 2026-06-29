// Package redisconn builds a redis.UniversalClient from config.RedisConfig.
// It supports standalone, cluster, and sentinel topologies, with optional TLS.
package redisconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/clavex-eu/clavex/internal/config"
	"github.com/redis/go-redis/v9"
)

// Open returns a connected redis.UniversalClient for the given config.
// The caller is responsible for calling Close() when done.
func Open(cfg config.RedisConfig) (redis.UniversalClient, error) {
	tlsCfg, err := buildTLS(cfg)
	if err != nil {
		return nil, fmt.Errorf("redis tls: %w", err)
	}

	var client redis.UniversalClient

	switch cfg.Mode {
	case config.RedisModeCluster:
		addrs := cfg.Addrs
		if len(addrs) == 0 && cfg.Addr != "" {
			addrs = []string{cfg.Addr}
		}
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        addrs,
			Password:     cfg.Password,
			PoolSize:     cfg.PoolSize,
			MinIdleConns: cfg.MinIdleConn,
			TLSConfig:    tlsCfg,
		})

	case config.RedisModeSentinel:
		sentinelAddrs := cfg.SentinelAddrs
		if len(sentinelAddrs) == 0 && cfg.Addr != "" {
			sentinelAddrs = []string{cfg.Addr}
		}
		masterName := cfg.MasterName
		if masterName == "" {
			masterName = "mymaster"
		}
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       masterName,
			SentinelAddrs:    sentinelAddrs,
			SentinelPassword: cfg.SentinelPassword,
			Password:         cfg.Password,
			DB:               cfg.DB,
			PoolSize:         cfg.PoolSize,
			MinIdleConns:     cfg.MinIdleConn,
			TLSConfig:        tlsCfg,
		})

	default: // standalone
		addr := cfg.Addr
		if addr == "" {
			addr = "localhost:6379"
		}
		client = redis.NewClient(&redis.Options{
			Addr:         addr,
			Password:     cfg.Password,
			DB:           cfg.DB,
			PoolSize:     cfg.PoolSize,
			MinIdleConns: cfg.MinIdleConn,
			TLSConfig:    tlsCfg,
		})
	}

	if err := client.Ping(context.Background()).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping (%s): %w", cfg.Mode, err)
	}
	return client, nil
}

func buildTLS(cfg config.RedisConfig) (*tls.Config, error) {
	if !cfg.TLSEnabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.TLSCAFile != "" {
		pemBytes, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid certs in %s", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
