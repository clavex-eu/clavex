package connectorregistry

// Built-in email delivery connectors.
// The "smtp" connector wraps the standard net/smtp delivery.
// The remaining connectors (aws_ses, sendgrid, mailgun) use their HTTP APIs.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"sort"
	"strings"
	"time"
)

func init() {
	RegisterEmail(&EmailConnectorDef{
		ID:          "smtp",
		DisplayName: "SMTP",
		ConfigSchema: []ConfigField{
			{Key: "host", Label: "SMTP Host", Type: "text", Required: true},
			{Key: "port", Label: "Port", Type: "number", Required: true, Placeholder: "587"},
			{Key: "username", Label: "Username", Type: "text", Required: false},
			{Key: "password", Label: "Password", Type: "password", Required: false},
			{Key: "from_address", Label: "From Address", Type: "text", Required: true,
				Placeholder: "no-reply@example.com"},
			{Key: "from_name", Label: "From Name", Type: "text", Required: false,
				Placeholder: "Acme Platform"},
			{Key: "use_tls", Label: "Use TLS", Type: "text", Required: false,
				Description: "Set to 'true' to use direct TLS (port 465). Omit for STARTTLS (port 587)."},
		},
	}, func(cfg map[string]any) (EmailSender, error) {
		host := cfgStrAny(cfg, "host")
		if host == "" {
			return nil, fmt.Errorf("smtp: host is required")
		}
		port := cfgStrAny(cfg, "port")
		if port == "" {
			port = "587"
		}
		return &smtpSender{
			host:        host,
			port:        port,
			username:    cfgStrAny(cfg, "username"),
			password:    cfgStrAny(cfg, "password"),
			fromAddress: cfgStrAny(cfg, "from_address"),
			fromName:    cfgStrAny(cfg, "from_name"),
			useTLS:      cfgStrAny(cfg, "use_tls") == "true",
		}, nil
	})

	RegisterEmail(&EmailConnectorDef{
		ID:          "aws_ses",
		DisplayName: "AWS SES",
		ConfigSchema: []ConfigField{
			{Key: "access_key_id", Label: "Access Key ID", Type: "text", Required: true},
			{Key: "secret_access_key", Label: "Secret Access Key", Type: "password", Required: true},
			{Key: "region", Label: "AWS Region", Type: "text", Required: true, Placeholder: "eu-west-1"},
			{Key: "from_address", Label: "From Address", Type: "text", Required: true,
				Description: "Must be a verified SES sender address or domain."},
			{Key: "from_name", Label: "From Name", Type: "text", Required: false},
		},
	}, func(cfg map[string]any) (EmailSender, error) {
		if cfgStrAny(cfg, "access_key_id") == "" || cfgStrAny(cfg, "region") == "" {
			return nil, fmt.Errorf("aws_ses: access_key_id and region are required")
		}
		return &sesSender{
			accessKeyID:     cfgStrAny(cfg, "access_key_id"),
			secretAccessKey: cfgStrAny(cfg, "secret_access_key"),
			region:          cfgStrAny(cfg, "region"),
			fromAddress:     cfgStrAny(cfg, "from_address"),
			fromName:        cfgStrAny(cfg, "from_name"),
		}, nil
	})

	RegisterEmail(&EmailConnectorDef{
		ID:          "sendgrid",
		DisplayName: "SendGrid",
		ConfigSchema: []ConfigField{
			{Key: "api_key", Label: "API Key", Type: "password", Required: true},
			{Key: "from_address", Label: "From Address", Type: "text", Required: true},
			{Key: "from_name", Label: "From Name", Type: "text", Required: false},
		},
	}, func(cfg map[string]any) (EmailSender, error) {
		if cfgStrAny(cfg, "api_key") == "" {
			return nil, fmt.Errorf("sendgrid: api_key is required")
		}
		return &sendgridSender{
			apiKey:      cfgStrAny(cfg, "api_key"),
			fromAddress: cfgStrAny(cfg, "from_address"),
			fromName:    cfgStrAny(cfg, "from_name"),
		}, nil
	})

	RegisterEmail(&EmailConnectorDef{
		ID:          "mailgun",
		DisplayName: "Mailgun",
		ConfigSchema: []ConfigField{
			{Key: "api_key", Label: "API Key (Private)", Type: "password", Required: true},
			{Key: "domain", Label: "Sending Domain", Type: "text", Required: true,
				Placeholder: "mg.example.com"},
			{Key: "region", Label: "Region", Type: "text", Required: false,
				Placeholder: "us", Description: "'us' (default) or 'eu' for the EU region."},
			{Key: "from_address", Label: "From Address", Type: "text", Required: true},
			{Key: "from_name", Label: "From Name", Type: "text", Required: false},
		},
	}, func(cfg map[string]any) (EmailSender, error) {
		if cfgStrAny(cfg, "api_key") == "" || cfgStrAny(cfg, "domain") == "" {
			return nil, fmt.Errorf("mailgun: api_key and domain are required")
		}
		region := cfgStrAny(cfg, "region")
		if region == "" {
			region = "us"
		}
		return &mailgunSender{
			apiKey:      cfgStrAny(cfg, "api_key"),
			domain:      cfgStrAny(cfg, "domain"),
			region:      region,
			fromAddress: cfgStrAny(cfg, "from_address"),
			fromName:    cfgStrAny(cfg, "from_name"),
		}, nil
	})
}

// ── SMTP ──────────────────────────────────────────────────────────────────────

type smtpSender struct {
	host, port              string
	username, password      string
	fromAddress, fromName   string
	useTLS                  bool
}

func (s *smtpSender) SendHTML(_ context.Context, to, subject, htmlBody string) error {
	addr := net.JoinHostPort(s.host, s.port)
	from := s.fromAddress
	if s.fromName != "" {
		from = s.fromName + " <" + s.fromAddress + ">"
	}
	msg := []byte(strings.Join([]string{
		"From: " + from,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"",
		htmlBody,
	}, "\r\n"))

	var auth smtp.Auth
	if s.username != "" {
		auth = smtp.PlainAuth("", s.username, s.password, s.host)
	}

	if s.useTLS {
		return s.sendTLS(addr, auth, to, msg)
	}
	return smtp.SendMail(addr, auth, s.fromAddress, []string{to}, msg)
}

func (s *smtpSender) sendTLS(addr string, auth smtp.Auth, to string, msg []byte) error {
	tlsCfg := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", addr, tlsCfg) //nolint:noctx
	if err != nil {
		return fmt.Errorf("smtp: TLS dial: %w", err)
	}
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("smtp: client: %w", err)
	}
	defer client.Quit() //nolint:errcheck
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := client.Mail(s.fromAddress); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err = wc.Write(msg); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	return wc.Close()
}

// ── AWS SES ───────────────────────────────────────────────────────────────────
// Uses SES SendEmail via HTTPS query API with AWS Signature Version 4.

type sesSender struct {
	accessKeyID, secretAccessKey, region string
	fromAddress, fromName                string
}

func (s *sesSender) SendHTML(ctx context.Context, to, subject, htmlBody string) error {
	service := "ses"
	host := fmt.Sprintf("email.%s.amazonaws.com", s.region)
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	from := s.fromAddress
	if s.fromName != "" {
		from = s.fromName + " <" + s.fromAddress + ">"
	}

	params := url.Values{
		"Action":                         {"SendEmail"},
		"Destination.ToAddresses.member.1": {to},
		"Message.Subject.Data":           {subject},
		"Message.Body.Html.Data":         {htmlBody},
		"Source":                         {from},
	}

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(params.Get(k)))
	}
	canonicalQuery := strings.Join(parts, "&")

	canonicalHeaders := "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-date"
	payloadHash := sesHashSHA256("")

	canonicalRequest := strings.Join([]string{
		"GET", "/", canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	credentialScope := datestamp + "/" + s.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, sesHashSHA256(canonicalRequest),
	}, "\n")

	signingKey := sesHMAC(
		sesHMAC(sesHMAC(sesHMAC([]byte("AWS4"+s.secretAccessKey), datestamp), s.region), service),
		"aws4_request",
	)
	signature := hex.EncodeToString(sesHMAC(signingKey, stringToSign))

	authorization := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.accessKeyID, credentialScope, signedHeaders, signature,
	)

	reqURL := "https://" + host + "/?" + canonicalQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("aws_ses: build request: %w", err)
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", authorization)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("aws_ses: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aws_ses: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func sesHashSHA256(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func sesHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// ── SendGrid ──────────────────────────────────────────────────────────────────
// Docs: https://docs.sendgrid.com/api-reference/mail-send/mail-send

type sendgridSender struct {
	apiKey, fromAddress, fromName string
}

func (s *sendgridSender) SendHTML(ctx context.Context, to, subject, htmlBody string) error {
	type emailAddr struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	}
	type content struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	type personalization struct {
		To []emailAddr `json:"to"`
	}
	type body struct {
		Personalizations []personalization `json:"personalizations"`
		From             emailAddr         `json:"from"`
		Subject          string            `json:"subject"`
		Content          []content         `json:"content"`
	}

	payload := body{
		Personalizations: []personalization{{To: []emailAddr{{Email: to}}}},
		From:             emailAddr{Email: s.fromAddress, Name: s.fromName},
		Subject:          subject,
		Content:          []content{{Type: "text/html", Value: htmlBody}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sendgrid: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.sendgrid.com/v3/mail/send", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("sendgrid: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sendgrid: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sendgrid: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ── Mailgun ───────────────────────────────────────────────────────────────────
// Docs: https://documentation.mailgun.com/en/latest/api-sending.html

type mailgunSender struct {
	apiKey, domain, region  string
	fromAddress, fromName   string
}

func (s *mailgunSender) SendHTML(ctx context.Context, to, subject, htmlBody string) error {
	baseURL := "https://api.mailgun.net/v3"
	if s.region == "eu" {
		baseURL = "https://api.eu.mailgun.net/v3"
	}
	apiURL := fmt.Sprintf("%s/%s/messages", baseURL, s.domain)

	from := s.fromAddress
	if s.fromName != "" {
		from = s.fromName + " <" + s.fromAddress + ">"
	}
	form := url.Values{
		"from":    {from},
		"to":      {to},
		"subject": {subject},
		"html":    {htmlBody},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("mailgun: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", s.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("mailgun: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("mailgun: status %d: %s", resp.StatusCode, b)
	}
	return nil
}
