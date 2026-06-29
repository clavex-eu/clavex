// Package cibanotify — push.go
// Native mobile push notification delivery for CIBA via APNs (iOS) and
// Firebase Cloud Messaging v1 (Android).
//
// # APNs (Apple Push Notification service)
// Uses the HTTP/2 provider-token authentication scheme (RFC 7519 / Apple
// documentation). The per-org .p8 EC private key is used to sign a short-lived
// JWT (iss=teamID, kid=keyID) that is passed in the Authorization header.
// Provider tokens are cached in memory for 50 minutes (valid for 1 hour).
//
// # FCM HTTP v1 API
// Uses a Google service account JSON key to obtain an OAuth2 access token via
// the self-signed JWT assertion flow (RFC 7523). The access token is cached for
// 55 minutes (tokens are valid for 1 hour). Notifications are delivered to the
// FCM v1 endpoint: POST /v1/projects/{project_id}/messages:send.
//
// # Thread safety
// Both token caches use sync.Map and are safe for concurrent use.
package cibanotify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog/log"
)

// ── Shared types ──────────────────────────────────────────────────────────────

// DeviceToken is a push token registered by a user's mobile device.
type DeviceToken struct {
	// Platform is "apns" (iOS) or "fcm" (Android).
	Platform    string
	DeviceToken string
}

// ── APNs ──────────────────────────────────────────────────────────────────────

// APNsConfig holds the per-org Apple Push Notification service credentials.
type APNsConfig struct {
	// KeyP8 is the raw content of the .p8 file (PKCS#8 EC private key, PEM).
	KeyP8 string
	// KeyID is the 10-character key identifier from the Apple Developer portal.
	KeyID string
	// TeamID is the Apple Developer team identifier (10 characters).
	TeamID string
	// BundleID is the app bundle identifier, used as the APNs topic.
	BundleID string
	// Production selects api.push.apple.com (true) or
	// api.sandbox.push.apple.com (false).
	Production bool
}

// FCMConfig holds the per-org Firebase Cloud Messaging v1 credentials.
type FCMConfig struct {
	// ServiceAccountJSON is the full content of the Google service account
	// key JSON file downloaded from the Firebase console.
	ServiceAccountJSON string
}

// PushSender delivers push notifications to mobile devices.
type PushSender interface {
	SendPush(ctx context.Context, p Params) error
}

// PushChannel implements PushSender for APNs and FCM.
type PushChannel struct {
	apns *APNsConfig
	fcm  *FCMConfig
}

// NewPushChannel creates a PushChannel. Either config may be nil to disable
// that platform.
func NewPushChannel(apns *APNsConfig, fcm *FCMConfig) *PushChannel {
	return &PushChannel{apns: apns, fcm: fcm}
}

// SendPush delivers notifications to every device token in p.DeviceTokens.
// Errors from individual sends are logged and do not prevent subsequent sends;
// the first encountered error is returned.
func (pc *PushChannel) SendPush(ctx context.Context, p Params) error {
	var firstErr error
	for _, dt := range p.DeviceTokens {
		var err error
		switch dt.Platform {
		case "apns":
			if pc.apns != nil {
				err = sendAPNs(ctx, *pc.apns, dt.DeviceToken, p)
			}
		case "fcm":
			if pc.fcm != nil {
				err = sendFCM(ctx, *pc.fcm, dt.DeviceToken, p)
			}
		}
		if err != nil {
			log.Warn().Err(err).
				Str("platform", dt.Platform).
				Str("auth_req_id", p.AuthReqID).
				Msg("ciba-push: delivery failed")
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ── APNs implementation ───────────────────────────────────────────────────────

const (
	apnsProductionHost = "https://api.push.apple.com"
	apnsSandboxHost    = "https://api.sandbox.push.apple.com"
	apnsTokenTTL       = 55 * time.Minute // APNs tokens valid 60 min; refresh at 55
)

type cachedAPNsToken struct {
	token     string
	expiresAt time.Time
}

// apnsTokenCache: cacheKey (keyID+":"+teamID) → *cachedAPNsToken
var apnsTokenCache sync.Map

// apnsHTTPClient is shared so HTTP/2 connections are reused across requests.
// Go's http.Transport negotiates HTTP/2 via ALPN for all HTTPS connections.
var apnsHTTPClient = &http.Client{Timeout: 10 * time.Second}

func getAPNsJWT(cfg APNsConfig) (string, error) {
	cacheKey := cfg.KeyID + ":" + cfg.TeamID
	if v, ok := apnsTokenCache.Load(cacheKey); ok {
		c := v.(*cachedAPNsToken)
		if time.Until(c.expiresAt) > time.Minute {
			return c.token, nil
		}
	}

	// Parse the .p8 PKCS#8 EC private key.
	privKey, err := parseECPrivKey(cfg.KeyP8)
	if err != nil {
		return "", fmt.Errorf("apns: parse .p8 key: %w", err)
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(cfg.TeamID).
		IssuedAt(now).
		Build()
	if err != nil {
		return "", fmt.Errorf("apns: build jwt: %w", err)
	}

	// APNs requires the kid header; set it via protected headers.
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, cfg.KeyID); err != nil {
		return "", fmt.Errorf("apns: set kid header: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("apns: sign jwt: %w", err)
	}

	token := string(signed)
	apnsTokenCache.Store(cacheKey, &cachedAPNsToken{
		token:     token,
		expiresAt: now.Add(apnsTokenTTL),
	})
	return token, nil
}

type apnsAlertBody struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type apnsAPS struct {
	Alert            apnsAlertBody `json:"alert"`
	Badge            int           `json:"badge"`
	Sound            string        `json:"sound"`
	ContentAvailable int           `json:"content-available"`
}

type apnsPayload struct {
	APS          apnsAPS `json:"aps"`
	AuthReqID    string  `json:"auth_req_id"`
	ApproveURL   string  `json:"approve_url"`
	DenyURL      string  `json:"deny_url"`
	ExpiresIn    int     `json:"expires_in"`
	// VPRequestURI is the openid4vp:// deep link for CIBA+OID4VP SCA flows.
	// Non-empty signals the wallet app to open the credential presentation flow
	// instead of showing a simple approve/deny prompt.
	VPRequestURI string  `json:"vp_request_uri,omitempty"`
}

func sendAPNs(ctx context.Context, cfg APNsConfig, deviceToken string, p Params) error {
	providerToken, err := getAPNsJWT(cfg)
	if err != nil {
		return err
	}

	body := apnsPayload{
		APS: apnsAPS{
			Alert: apnsAlertBody{
				Title: p.AppName,
				Body:  p.BindingMessage,
			},
			Badge:            1,
			Sound:            "default",
			ContentAvailable: 1,
		},
		AuthReqID:    p.AuthReqID,
		ApproveURL:   p.ApproveURL,
		DenyURL:      p.DenyURL,
		ExpiresIn:    p.ExpiresIn,
		VPRequestURI: p.VPRequestURI,
	}

	rawBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("apns: marshal payload: %w", err)
	}

	host := apnsSandboxHost
	if cfg.Production {
		host = apnsProductionHost
	}
	endpoint := host + "/3/device/" + deviceToken

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return fmt.Errorf("apns: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+providerToken)
	req.Header.Set("apns-topic", cfg.BundleID)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("Content-Type", "application/json")

	resp, err := apnsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("apns: send: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode != http.StatusOK {
		// Invalidate the cached token on 403 (token expired / invalid).
		if resp.StatusCode == http.StatusForbidden {
			apnsTokenCache.Delete(cfg.KeyID + ":" + cfg.TeamID)
		}
		return fmt.Errorf("apns: server returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// ── FCM HTTP v1 implementation ────────────────────────────────────────────────

const (
	fcmTokenURI    = "https://oauth2.googleapis.com/token"
	fcmMessagesURL = "https://fcm.googleapis.com/v1/projects/%s/messages:send"
	fcmScope       = "https://www.googleapis.com/auth/firebase.messaging"
	fcmTokenTTL    = 55 * time.Minute
)

type serviceAccountJSON struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

type cachedFCMToken struct {
	accessToken string
	expiresAt   time.Time
}

// fcmTokenCache: clientEmail → *cachedFCMToken
var fcmTokenCache sync.Map

var fcmHTTPClient = &http.Client{Timeout: 15 * time.Second}

func parseFCMConfig(raw string) (serviceAccountJSON, error) {
	var sa serviceAccountJSON
	if err := json.Unmarshal([]byte(raw), &sa); err != nil {
		return sa, fmt.Errorf("fcm: parse service account json: %w", err)
	}
	if sa.Type != "service_account" {
		return sa, fmt.Errorf("fcm: expected type=service_account, got %q", sa.Type)
	}
	if sa.ClientEmail == "" || sa.ProjectID == "" || sa.PrivateKey == "" {
		return sa, fmt.Errorf("fcm: service account json missing required fields")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = fcmTokenURI
	}
	return sa, nil
}

func getFCMAccessToken(ctx context.Context, sa serviceAccountJSON) (string, error) {
	if v, ok := fcmTokenCache.Load(sa.ClientEmail); ok {
		c := v.(*cachedFCMToken)
		if time.Until(c.expiresAt) > time.Minute {
			return c.accessToken, nil
		}
	}

	privKey, err := parseRSAPrivKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("fcm: parse private key: %w", err)
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(sa.ClientEmail).
		Subject(sa.ClientEmail).
		Audience([]string{sa.TokenURI}).
		IssuedAt(now).
		Expiration(now.Add(time.Hour)).
		Claim("scope", fcmScope).
		Build()
	if err != nil {
		return "", fmt.Errorf("fcm: build jwt: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		return "", fmt.Errorf("fcm: sign service account jwt: %w", err)
	}

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {string(signed)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sa.TokenURI,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("fcm: token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := fcmHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fcm: token exchange: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("fcm: decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("fcm: empty access token in token exchange response")
	}

	ttl := fcmTokenTTL
	if tokenResp.ExpiresIn > 0 {
		ttl = time.Duration(tokenResp.ExpiresIn)*time.Second - 5*time.Minute
	}
	fcmTokenCache.Store(sa.ClientEmail, &cachedFCMToken{
		accessToken: tokenResp.AccessToken,
		expiresAt:   now.Add(ttl),
	})
	return tokenResp.AccessToken, nil
}

type fcmMessage struct {
	Token        string            `json:"token"`
	Notification fcmNotification   `json:"notification"`
	Data         map[string]string `json:"data"`
	Android      fcmAndroid        `json:"android"`
}

type fcmNotification struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type fcmAndroid struct {
	Priority string `json:"priority"`
}

func sendFCM(ctx context.Context, cfg FCMConfig, deviceToken string, p Params) error {
	sa, err := parseFCMConfig(cfg.ServiceAccountJSON)
	if err != nil {
		return err
	}

	accessToken, err := getFCMAccessToken(ctx, sa)
	if err != nil {
		return err
	}

	msg := fcmMessage{
		Token: deviceToken,
		Notification: fcmNotification{
			Title: p.AppName,
			Body:  p.BindingMessage,
		},
		Data: map[string]string{
			"auth_req_id":   p.AuthReqID,
			"approve_url":   p.ApproveURL,
			"deny_url":      p.DenyURL,
			"expires_in":    fmt.Sprintf("%d", p.ExpiresIn),
			"vp_request_uri": p.VPRequestURI,
		},
		Android: fcmAndroid{Priority: "high"},
	}

	body := map[string]any{"message": msg}
	rawBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("fcm: marshal message: %w", err)
	}

	endpoint := fmt.Sprintf(fcmMessagesURL, sa.ProjectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(rawBody))
	if err != nil {
		return fmt.Errorf("fcm: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := fcmHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fcm: send: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))

	if resp.StatusCode != http.StatusOK {
		// Invalidate the cached access token on 401.
		if resp.StatusCode == http.StatusUnauthorized {
			fcmTokenCache.Delete(sa.ClientEmail)
		}
		return fmt.Errorf("fcm: server returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// ── Key parsing helpers ───────────────────────────────────────────────────────

// parseECPrivKey decodes a PEM-encoded PKCS#8 EC private key (as produced by
// Apple's .p8 download from the Developer portal).
func parseECPrivKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePKCS8PrivateKey: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", key)
	}
	return ec, nil
}

// parseRSAPrivKey decodes a PEM-encoded RSA private key (PKCS#8 or PKCS#1),
// as found in Google service account JSON files.
func parseRSAPrivKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ParsePKCS8PrivateKey: %w", err)
		}
		rsakey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
		return rsakey, nil
	case "RSA PRIVATE KEY": // PKCS#1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
}
