package connectorregistry

// Built-in SMS gateway connectors.
// Each init() call registers the connector into the catalog so that sms.ForOrg
// can instantiate it from the provider string stored in org_sms_settings.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func init() {
	RegisterSMS(&SMSConnectorDef{
		ID:          "twilio",
		DisplayName: "Twilio",
		ConfigSchema: []ConfigField{
			{Key: "account_sid", Label: "Account SID", Type: "text", Required: true},
			{Key: "auth_token", Label: "Auth Token", Type: "password", Required: true},
			{Key: "from", Label: "From Number", Type: "text", Required: true,
				Placeholder: "+14155552671",
				Description: "The Twilio phone number or Messaging Service SID to send from."},
		},
	}, func(cfg map[string]any) (SMSSender, error) {
		sid := cfgStrAny(cfg, "account_sid")
		if sid == "" {
			return nil, fmt.Errorf("twilio: account_sid is required")
		}
		return &twilioSender{
			accountSID: sid,
			authToken:  cfgStrAny(cfg, "auth_token"),
			from:       cfgStrAny(cfg, "from"),
		}, nil
	})

	RegisterSMS(&SMSConnectorDef{
		ID:          "vonage",
		DisplayName: "Vonage (Nexmo)",
		ConfigSchema: []ConfigField{
			{Key: "api_key", Label: "API Key", Type: "text", Required: true},
			{Key: "api_secret", Label: "API Secret", Type: "password", Required: true},
			{Key: "from", Label: "From", Type: "text", Required: true,
				Description: "Sender number or name (max 11 alphanumeric chars for virtual number)."},
		},
	}, func(cfg map[string]any) (SMSSender, error) {
		if cfgStrAny(cfg, "api_key") == "" {
			return nil, fmt.Errorf("vonage: api_key is required")
		}
		return &vonageSender{
			apiKey:    cfgStrAny(cfg, "api_key"),
			apiSecret: cfgStrAny(cfg, "api_secret"),
			from:      cfgStrAny(cfg, "from"),
		}, nil
	})

	RegisterSMS(&SMSConnectorDef{
		ID:          "aws_sns",
		DisplayName: "AWS SNS",
		ConfigSchema: []ConfigField{
			{Key: "access_key_id", Label: "Access Key ID", Type: "text", Required: true},
			{Key: "secret_access_key", Label: "Secret Access Key", Type: "password", Required: true},
			{Key: "region", Label: "AWS Region", Type: "text", Required: true,
				Placeholder: "eu-west-1"},
			{Key: "sender_id", Label: "Sender ID", Type: "text", Required: false,
				Description: "Optional SMS sender name shown to recipients (not available in all countries)."},
		},
	}, func(cfg map[string]any) (SMSSender, error) {
		if cfgStrAny(cfg, "access_key_id") == "" || cfgStrAny(cfg, "region") == "" {
			return nil, fmt.Errorf("aws_sns: access_key_id and region are required")
		}
		return &snsSender{
			accessKeyID:     cfgStrAny(cfg, "access_key_id"),
			secretAccessKey: cfgStrAny(cfg, "secret_access_key"),
			region:          cfgStrAny(cfg, "region"),
			senderID:        cfgStrAny(cfg, "sender_id"),
		}, nil
	})

	// Infobip — major EU / global SMS gateway.
	// Docs: https://www.infobip.com/docs/api/channels/sms/sms-messaging/outbound-sms/send-sms-message
	RegisterSMS(&SMSConnectorDef{
		ID:          "infobip",
		DisplayName: "Infobip",
		ConfigSchema: []ConfigField{
			{Key: "base_url", Label: "Base URL", Type: "url", Required: true,
				Placeholder: "https://XXXXX.api.infobip.com",
				Description: "Your personal Infobip API base URL (found in the Infobip portal)."},
			{Key: "api_key", Label: "API Key", Type: "password", Required: true},
			{Key: "sender", Label: "Sender", Type: "text", Required: true,
				Description: "Alphanumeric sender ID or phone number."},
		},
	}, func(cfg map[string]any) (SMSSender, error) {
		base := cfgStrAny(cfg, "base_url")
		if base == "" {
			return nil, fmt.Errorf("infobip: base_url is required")
		}
		if cfgStrAny(cfg, "api_key") == "" {
			return nil, fmt.Errorf("infobip: api_key is required")
		}
		return &infobipSender{
			baseURL: strings.TrimRight(base, "/"),
			apiKey:  cfgStrAny(cfg, "api_key"),
			sender:  cfgStrAny(cfg, "sender"),
		}, nil
	})

	// WhatsApp Business — Meta Cloud API.
	// Common in EU B2C markets where WhatsApp adoption exceeds SMS.
	// Docs: https://developers.facebook.com/docs/whatsapp/cloud-api/messages/text-messages
	RegisterSMS(&SMSConnectorDef{
		ID:          "whatsapp",
		DisplayName: "WhatsApp Business",
		ConfigSchema: []ConfigField{
			{Key: "access_token", Label: "System User Access Token", Type: "password", Required: true,
				Description: "Permanent System User access token from the Meta Business suite."},
			{Key: "phone_number_id", Label: "Phone Number ID", Type: "text", Required: true,
				Description: "The numeric ID of the WhatsApp Business phone number to send from."},
		},
	}, func(cfg map[string]any) (SMSSender, error) {
		if cfgStrAny(cfg, "access_token") == "" || cfgStrAny(cfg, "phone_number_id") == "" {
			return nil, fmt.Errorf("whatsapp: access_token and phone_number_id are required")
		}
		return &whatsappSender{
			accessToken:   cfgStrAny(cfg, "access_token"),
			phoneNumberID: cfgStrAny(cfg, "phone_number_id"),
		}, nil
	})
}

// cfgStrAny safely reads a string value from an any-typed config map.
func cfgStrAny(cfg map[string]any, key string) string {
	v, _ := cfg[key].(string)
	return v
}

// ── Twilio ────────────────────────────────────────────────────────────────────

type twilioSender struct {
	accountSID, authToken, from string
}

func (p *twilioSender) Send(ctx context.Context, to, body string) error {
	apiURL := "https://api.twilio.com/2010-04-01/Accounts/" + p.accountSID + "/Messages.json"
	form := url.Values{"To": {to}, "From": {p.from}, "Body": {body}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("twilio: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.accountSID, p.authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("twilio: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("twilio: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ── Vonage ────────────────────────────────────────────────────────────────────

type vonageSender struct {
	apiKey, apiSecret, from string
}

func (p *vonageSender) Send(ctx context.Context, to, body string) error {
	form := url.Values{
		"api_key":    {p.apiKey},
		"api_secret": {p.apiSecret},
		"from":       {p.from},
		"to":         {to},
		"text":       {body},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://rest.nexmo.com/sms/json", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("vonage: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("vonage: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vonage: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ── AWS SNS ───────────────────────────────────────────────────────────────────

type snsSender struct {
	accessKeyID, secretAccessKey, region, senderID string
}

func (p *snsSender) Send(ctx context.Context, to, body string) error {
	return snsPublishInternal(ctx, p.accessKeyID, p.secretAccessKey, p.region, p.senderID, to, body)
}

// snsPublishInternal sends an SMS via Amazon SNS using the query-string API with
// AWS Signature Version 4 signing (no AWS SDK dependency).
func snsPublishInternal(ctx context.Context, accessKeyID, secretKey, region, senderID, to, body string) error {
	service := "sns"
	host := fmt.Sprintf("sns.%s.amazonaws.com", region)
	endpoint := "https://" + host + "/"
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")

	params := url.Values{
		"Action":      {"Publish"},
		"Message":     {body},
		"PhoneNumber": {to},
		"Version":     {"2010-03-31"},
	}
	if senderID != "" {
		params.Set("MessageAttributes.entry.1.Name", "AWS.SNS.SMS.SenderID")
		params.Set("MessageAttributes.entry.1.Value.DataType", "String")
		params.Set("MessageAttributes.entry.1.Value.StringValue", senderID)
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
	payloadHash := snsSHA256("")

	canonicalRequest := strings.Join([]string{
		"GET", "/", canonicalQuery, canonicalHeaders, signedHeaders, payloadHash,
	}, "\n")

	credentialScope := datestamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, snsSHA256(canonicalRequest),
	}, "\n")

	signingKey := snsHMAC(
		snsHMAC(snsHMAC(snsHMAC([]byte("AWS4"+secretKey), datestamp), region), service),
		"aws4_request",
	)
	signature := hex.EncodeToString(snsHMAC(signingKey, stringToSign))

	authorization := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKeyID, credentialScope, signedHeaders, signature,
	)

	reqURL := endpoint + "?" + canonicalQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return fmt.Errorf("aws_sns: build request: %w", err)
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("Authorization", authorization)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("aws_sns: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("aws_sns: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func snsSHA256(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func snsHMAC(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// ── Infobip ───────────────────────────────────────────────────────────────────
// Docs: https://www.infobip.com/docs/api/channels/sms/sms-messaging/outbound-sms/send-sms-message

type infobipSender struct {
	baseURL, apiKey, sender string
}

func (p *infobipSender) Send(ctx context.Context, to, body string) error {
	type destination struct {
		To string `json:"to"`
	}
	type message struct {
		From         string        `json:"from,omitempty"`
		Destinations []destination `json:"destinations"`
		Text         string        `json:"text"`
	}
	type payload struct {
		Messages []message `json:"messages"`
	}

	data, err := json.Marshal(payload{
		Messages: []message{{
			From:         p.sender,
			Destinations: []destination{{To: to}},
			Text:         body,
		}},
	})
	if err != nil {
		return fmt.Errorf("infobip: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/sms/2/text/advanced", strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("infobip: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "App "+p.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("infobip: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("infobip: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ── WhatsApp Business ─────────────────────────────────────────────────────────
// Uses the Meta Cloud API (WhatsApp Business Platform).
// Docs: https://developers.facebook.com/docs/whatsapp/cloud-api/messages/text-messages

type whatsappSender struct {
	accessToken, phoneNumberID string
}

func (p *whatsappSender) Send(ctx context.Context, to, body string) error {
	type textPayload struct {
		PreviewURL bool   `json:"preview_url"`
		Body       string `json:"body"`
	}
	type msg struct {
		MessagingProduct string      `json:"messaging_product"`
		RecipientType    string      `json:"recipient_type"`
		To               string      `json:"to"`
		Type             string      `json:"type"`
		Text             textPayload `json:"text"`
	}
	data, err := json.Marshal(msg{
		MessagingProduct: "whatsapp",
		RecipientType:    "individual",
		To:               to,
		Type:             "text",
		Text:             textPayload{PreviewURL: false, Body: body},
	})
	if err != nil {
		return fmt.Errorf("whatsapp: marshal: %w", err)
	}

	apiURL := "https://graph.facebook.com/v19.0/" + p.phoneNumberID + "/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(string(data)))
	if err != nil {
		return fmt.Errorf("whatsapp: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whatsapp: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("whatsapp: status %d: %s", resp.StatusCode, b)
	}
	return nil
}
