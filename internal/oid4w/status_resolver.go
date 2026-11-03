package oid4w

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
)

var ErrStatusUnavailable = errors.New("status service unavailable")
var ErrStatusInvalid = errors.New("invalid status token")

type statusCacheEntry struct {
	list           *ValidatedStatusList
	until, lastUse time.Time
}
type statusFlight struct {
	done chan struct{}
	list *ValidatedStatusList
	err  error
}

type StatusResolver struct {
	client     *http.Client
	mu         sync.Mutex
	cache      map[string]*statusCacheEntry
	flights    map[string]*statusFlight
	perScope   map[string]int
	crls       map[string]*cachedCRL
	crlFlights map[string]*crlFlight
	cacheBytes int
	now        func() time.Time
}

func NewStatusResolver() *StatusResolver { return NewStatusResolverWithHTTPClient(statusHTTPClient()) }

// An injected client is a trusted embedding/test dependency. Application wiring
// never obtains it from tenant settings and must preserve transport controls.
func NewStatusResolverWithHTTPClient(client *http.Client) *StatusResolver {
	if client == nil {
		client = statusHTTPClient()
	}
	copyClient := *client
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if copyClient.Timeout <= 0 || copyClient.Timeout > 3*time.Second {
		copyClient.Timeout = 3 * time.Second
	}
	client = &copyClient
	return &StatusResolver{client: client, cache: map[string]*statusCacheEntry{}, flights: map[string]*statusFlight{}, perScope: map[string]int{}, crls: map[string]*cachedCRL{}, crlFlights: map[string]*crlFlight{}, now: time.Now}
}

func statusCacheKey(scope string, source StatusSource, uri string) string {
	encoded, _ := json.Marshal([]any{scope, source, uri})
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}

func (r *StatusResolver) Check(ctx context.Context, scope string, source StatusSource, ref StatusClaim) error {
	if ctx.Err() != nil {
		return ErrStatusUnavailable
	}
	if scope == "" || len(scope) > 1024 {
		return ErrStatusInvalid
	}
	if err := source.Validate(); err != nil {
		return fmt.Errorf("%w: invalid status policy", ErrStatusUnavailable)
	}
	allowed := false
	for _, uri := range source.ListURIs {
		if uri == ref.StatusList.URI {
			allowed = true
		}
	}
	if !allowed {
		return ErrStatusInvalid
	}
	if _, err := StatusURL(ref.StatusList.URI); err != nil {
		return ErrStatusInvalid
	}
	key := statusCacheKey(scope, source, ref.StatusList.URI)
	now := r.now()
	r.mu.Lock()
	if entry := r.cache[key]; entry != nil {
		if now.Before(entry.until) {
			entry.lastUse = now
			list := entry.list
			r.mu.Unlock()
			return list.Check(ref.StatusList.IDX)
		}
		r.cacheBytes -= len(entry.list.data)
		delete(r.cache, key)
	}
	if flight := r.flights[key]; flight != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return ErrStatusUnavailable
		case <-flight.done:
		}
		if flight.err != nil {
			return flight.err
		}
		if !r.now().Before(flight.list.FreshUntil) {
			return ErrStatusUnavailable
		}
		return flight.list.Check(ref.StatusList.IDX)
	}
	if len(r.flights)+len(r.crlFlights) >= 32 || r.perScope[scope] >= 4 {
		r.mu.Unlock()
		return ErrStatusUnavailable
	}
	flight := &statusFlight{done: make(chan struct{})}
	r.flights[key] = flight
	r.perScope[scope]++
	r.mu.Unlock()
	list, until, err := r.fetch(ctx, source, ref)
	r.mu.Lock()
	delete(r.flights, key)
	r.perScope[scope]--
	if r.perScope[scope] == 0 {
		delete(r.perScope, scope)
	}
	flight.list, flight.err = list, err
	if err == nil && r.now().Before(until) && r.evictFor(len(list.data)) {
		r.cache[key] = &statusCacheEntry{list: list, until: until, lastUse: r.now()}
		r.cacheBytes += len(list.data)
	}
	close(flight.done)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if !r.now().Before(list.FreshUntil) {
		return ErrStatusUnavailable
	}
	return list.Check(ref.StatusList.IDX)
}

func (r *StatusResolver) fetch(ctx context.Context, source StatusSource, ref StatusClaim) (*ValidatedStatusList, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ref.StatusList.URI, nil)
	if err != nil {
		return nil, time.Time{}, ErrStatusInvalid
	}
	req.Header.Set("Accept", "application/statuslist+jwt")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, time.Time{}, ErrStatusUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, time.Time{}, ErrStatusUnavailable
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/statuslist+jwt" {
		return nil, time.Time{}, ErrStatusInvalid
	}
	encoding := response.Header.Get("Content-Encoding")
	if encoding != "" && encoding != "identity" {
		return nil, time.Time{}, ErrStatusInvalid
	}
	if response.ContentLength > 512*1024 {
		return nil, time.Time{}, ErrStatusInvalid
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 512*1024+1))
	if err != nil {
		return nil, time.Time{}, ErrStatusUnavailable
	}
	if len(body) > 512*1024 {
		return nil, time.Time{}, ErrStatusInvalid
	}
	message, err := jws.Parse(body)
	if err != nil || len(message.Signatures()) != 1 {
		return nil, time.Time{}, ErrStatusInvalid
	}
	keys, err := source.keys()
	if err != nil {
		return nil, time.Time{}, ErrStatusUnavailable
	}
	maxAge := source.MaxAgeSeconds
	if maxAge == 0 {
		maxAge = 300
	}
	var list *ValidatedStatusList
	for _, key := range keys {
		kid := message.Signatures()[0].ProtectedHeaders().KeyID()
		if kid != "" && key.KeyID() != kid {
			continue
		}
		var public crypto.PublicKey
		if key.Raw(&public) != nil {
			continue
		}
		validationRef := ref
		validationRef.StatusList.IDX = 0
		list, err = ValidateStatusListToken(string(body), validationRef, source.StatusIssuer, public, r.now(), time.Duration(maxAge)*time.Second, StatusValidationPolicy{RequireIssuerClaim: source.RequireIssuerClaim, RequireExpiration: source.RequireExpiration})
		if err == nil {
			break
		}
	}
	if list == nil || err != nil {
		return nil, time.Time{}, ErrStatusInvalid
	}
	until := list.FreshUntil
	cache := 60
	if source.CacheSeconds != nil {
		cache = *source.CacheSeconds
	}
	if deadline := r.now().Add(time.Duration(cache) * time.Second); deadline.Before(until) {
		until = deadline
	}
	until, err = httpCacheDeadline(response.Header, r.now(), until)
	if err != nil {
		return nil, time.Time{}, err
	}
	return list, until, nil
}

// Caller holds mu. Cache space and eviction are shared by JWT lists and CRLs.
func (r *StatusResolver) evictFor(size int) bool {
	if size > 16*1024*1024 {
		return false
	}
	for len(r.cache)+len(r.crls) >= 128 || r.cacheBytes+size > 16*1024*1024 {
		oldest := ""
		var at time.Time
		isCRL := false
		for k, v := range r.cache {
			if oldest == "" || v.lastUse.Before(at) {
				oldest, at, isCRL = k, v.lastUse, false
			}
		}
		for k, v := range r.crls {
			if oldest == "" || v.lastUse.Before(at) {
				oldest, at, isCRL = k, v.lastUse, true
			}
		}
		if oldest == "" {
			return false
		}
		if isCRL {
			r.cacheBytes -= r.crls[oldest].size
			delete(r.crls, oldest)
		} else {
			r.cacheBytes -= len(r.cache[oldest].list.data)
			delete(r.cache, oldest)
		}
	}
	return true
}

func httpCacheDeadline(headers http.Header, now, until time.Time) (time.Time, error) {
	age := 0
	if text := headers.Get("Age"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 0 {
			return time.Time{}, ErrStatusUnavailable
		}
		age = value
	}
	for _, part := range strings.Split(headers.Get("Cache-Control"), ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "no-cache" || part == "no-store" {
			until = now
		}
		if strings.HasPrefix(part, "max-age=") {
			seconds, err := strconv.Atoi(strings.Trim(strings.TrimPrefix(part, "max-age="), `"`))
			if err == nil && seconds >= 0 && age > 0 && age >= seconds {
				return time.Time{}, ErrStatusUnavailable
			}
			if err != nil || seconds <= 0 {
				until = now
				continue
			}
			if seconds > 86400 {
				seconds = 86400
			}
			deadline := now.Add(time.Duration(seconds-age) * time.Second)
			if deadline.Before(until) {
				until = deadline
			}
		}
	}
	return until, nil
}
