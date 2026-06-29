// Package captcha provides server-side verification for CAPTCHA challenges.
// Supported providers: Cloudflare Turnstile, hCaptcha, reCAPTCHA v2.
package captcha

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ProviderTurnstile = "turnstile"
	ProviderHcaptcha  = "hcaptcha"
	ProviderRecaptcha = "recaptcha"

	turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	hcaptchaVerifyURL  = "https://hcaptcha.com/siteverify"
	recaptchaVerifyURL = "https://www.google.com/recaptcha/api/siteverify"
)

// Verifier checks a CAPTCHA token as returned by the browser widget.
type Verifier interface {
	// Verify returns nil if the token is valid for the given remote IP.
	Verify(ctx context.Context, token, remoteIP string) error
	// SiteKey is the public key injected into the login template.
	SiteKey() string
	// ScriptURL is the URL of the provider's JS widget script.
	ScriptURL() string
}

// New constructs a Verifier for the given provider.
func New(provider, siteKey, secretKey string) (Verifier, error) {
	switch provider {
	case ProviderTurnstile:
		return &genericVerifier{
			siteKey:   siteKey,
			secretKey: secretKey,
			verifyURL: turnstileVerifyURL,
			scriptURL: "https://challenges.cloudflare.com/turnstile/v0/api.js",
		}, nil
	case ProviderHcaptcha:
		return &genericVerifier{
			siteKey:   siteKey,
			secretKey: secretKey,
			verifyURL: hcaptchaVerifyURL,
			scriptURL: "https://js.hcaptcha.com/1/api.js",
		}, nil
	case ProviderRecaptcha:
		return &genericVerifier{
			siteKey:   siteKey,
			secretKey: secretKey,
			verifyURL: recaptchaVerifyURL,
			scriptURL: "https://www.google.com/recaptcha/api.js",
		}, nil
	default:
		return nil, fmt.Errorf("unsupported captcha provider: %s", provider)
	}
}

// genericVerifier works for any provider that exposes the standard siteverify API.
type genericVerifier struct {
	siteKey   string
	secretKey string
	verifyURL string
	scriptURL string
}

func (v *genericVerifier) SiteKey() string   { return v.siteKey }
func (v *genericVerifier) ScriptURL() string { return v.scriptURL }

func (v *genericVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	if token == "" {
		return fmt.Errorf("captcha token is missing")
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("secret", v.secretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctxTimeout, http.MethodPost, v.verifyURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("captcha verification request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("captcha verification failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool     `json:"success"`
		Errors  []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("captcha response parse error: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("captcha verification failed: %v", result.Errors)
	}
	return nil
}
