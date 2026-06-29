package assets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LocalClient is a Backend implementation that stores assets on the local
// filesystem. It is intended as a zero-dependency fallback for single-node
// deployments that do not have an S3-compatible object store.
//
// Files are written to BaseDir/<key> and served at BaseURL/<key>.
// BaseURL must be an absolute HTTP(S) URL reachable by browser clients.
// The server is responsible for mounting a static file handler at the
// same path prefix (see server.go, "_assets" route).
type LocalClient struct {
	baseDir string
	baseURL string
}

// NewLocalClient creates a LocalClient.
// baseDir is the directory where uploaded files are written (created if absent).
// baseURL is the public URL prefix (e.g. "https://auth.example.com/_assets").
func NewLocalClient(baseDir, baseURL string) (*LocalClient, error) {
	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return nil, fmt.Errorf("assets/local: create base dir %q: %w", baseDir, err)
	}
	return &LocalClient{
		baseDir: strings.TrimRight(baseDir, "/"),
		baseURL: strings.TrimRight(baseURL, "/"),
	}, nil
}

// PublicURL returns the public download URL for key.
func (c *LocalClient) PublicURL(key string) string {
	return c.baseURL + "/" + strings.TrimLeft(key, "/")
}

// PutObject writes body to disk at baseDir/<key> (creating intermediate
// directories as needed) and returns the public URL.
func (c *LocalClient) PutObject(_ context.Context, key, _ string, body []byte) (string, error) {
	dest := filepath.Join(c.baseDir, filepath.FromSlash(strings.TrimLeft(key, "/")))

	// Prevent directory traversal: the resolved path must stay inside baseDir.
	absBase, err := filepath.Abs(c.baseDir)
	if err != nil {
		return "", fmt.Errorf("assets/local: resolve base: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", fmt.Errorf("assets/local: resolve dest: %w", err)
	}
	if !strings.HasPrefix(absDest, absBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("assets/local: key escapes base directory")
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		return "", fmt.Errorf("assets/local: mkdir: %w", err)
	}

	// Write atomically via a temp file in the same directory.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".upload-*")
	if err != nil {
		return "", fmt.Errorf("assets/local: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("assets/local: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("assets/local: close temp: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("assets/local: rename: %w", err)
	}

	return c.PublicURL(key), nil
}

// DeleteObject removes the file at baseDir/<key>. Returns nil if the file
// does not exist (idempotent).
func (c *LocalClient) DeleteObject(_ context.Context, key string) error {
	dest := filepath.Join(c.baseDir, filepath.FromSlash(strings.TrimLeft(key, "/")))

	absBase, err := filepath.Abs(c.baseDir)
	if err != nil {
		return fmt.Errorf("assets/local: resolve base: %w", err)
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("assets/local: resolve dest: %w", err)
	}
	if !strings.HasPrefix(absDest, absBase+string(os.PathSeparator)) {
		return fmt.Errorf("assets/local: key escapes base directory")
	}

	if err := os.Remove(dest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("assets/local: remove: %w", err)
	}
	return nil
}
