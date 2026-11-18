package ovirtsdk

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func renewalTestToken(expiresAt time.Time, sequence int) string {
	payload := fmt.Sprintf(`{"exp":%d,"sequence":%d}`, expiresAt.Unix(), sequence)
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func TestAuthenticationPublication(t *testing.T) {
	var requests int
	var authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			requests++
			fmt.Fprintf(w, `{"access_token":%q}`, renewalTestToken(time.Now().Add(time.Hour), requests))
			return
		}
		authorization = r.Header.Get("Authorization")
		fmt.Fprint(w, `<api/>`)
	}))
	defer server.Close()
	build := func() *Connection {
		conn, err := NewConnectionBuilder().URL(server.URL + "/ovirt-engine/api").Username("test").Password("test").Build()
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	conn := build()
	readerLock := conn.ssoLock
	service := conn.SystemService()
	t.Log("Initial authentication and deadline inspection leave the connection stable")
	if due, err := conn.ReconnectDue(time.Now()); err != nil || due || requests != 0 {
		t.Fatal("deadline inspection attempted authentication")
	}
	if err := conn.Authenticate(); err != nil {
		t.Fatal(err)
	}
	candidate := build()
	if err := candidate.Authenticate(); err != nil {
		t.Fatal(err)
	}
	t.Log("Publish candidate authentication to an existing service handle")
	if err := conn.ReplaceAuthentication(candidate); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get().Send(); err != nil || authorization != "Bearer "+candidate.ssoToken {
		t.Fatal("existing service did not see candidate authentication")
	}
	if conn.ssoLock != readerLock || conn.ssoTokenAcquiredAt != candidate.ssoTokenAcquiredAt ||
		!conn.ssoTokenExpiresAt.Equal(candidate.ssoTokenExpiresAt) {
		t.Fatal("publication replaced the reader lock or lost token timing")
	}
	previousToken, previousExpiry := conn.ssoToken, conn.ssoTokenExpiresAt
	for _, invalid := range []*Connection{
		nil,
		build(),
		{ssoLock: &sync.RWMutex{}, url: conn.url, username: "another-user", ssoToken: "sensitive-token"},
		{ssoLock: &sync.RWMutex{}, url: conn.url, username: conn.username, ssoToken: "sensitive-token", ssoTokenExpiresAt: time.Now().Add(-time.Minute)},
	} {
		t.Log("Reject invalid candidates without changing active authentication")
		if err := conn.ReplaceAuthentication(invalid); err == nil || strings.Contains(err.Error(), "sensitive-token") {
			t.Fatal("invalid publication succeeded or exposed token contents")
		}
		if conn.ssoToken != previousToken || !conn.ssoTokenExpiresAt.Equal(previousExpiry) {
			t.Fatal("invalid publication changed active authentication")
		}
	}
}

func TestConcurrentAuthenticationPublication(t *testing.T) {
	var serverLock sync.Mutex
	var requests int
	allowedTokens := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverLock.Lock()
		defer serverLock.Unlock()
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			requests++
			token := renewalTestToken(time.Now().Add(time.Hour), requests)
			allowedTokens["Bearer "+token] = true
			fmt.Fprintf(w, `{"access_token":%q}`, token)
			return
		}
		if !allowedTokens[r.Header.Get("Authorization")] {
			t.Error("API request used unpublished authentication")
		}
		fmt.Fprint(w, `<api/>`)
	}))
	defer server.Close()
	build := func() *Connection {
		conn, err := NewConnectionBuilder().URL(server.URL + "/ovirt-engine/api").Username("test").Password("test").Build()
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	conn := build()
	var wg sync.WaitGroup
	t.Log("Concurrent initial requests share a single login")
	for n := 0; n < 20; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := conn.Test(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	serverLock.Lock()
	initialRequests := requests
	serverLock.Unlock()
	if initialRequests != 1 {
		t.Fatalf("got %d initial logins, want one", initialRequests)
	}
	candidate := build()
	if err := candidate.Authenticate(); err != nil {
		t.Fatal(err)
	}
	t.Log("Concurrent SDK reads and candidate publication share the stable reader lock")
	for n := 0; n < 20; n++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := conn.ReplaceAuthentication(candidate); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := conn.Test(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestTokenExpiryClaims(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		want          int64
	}{
		{name: "real deployment lifetime", payload: `{"iat":1794278349,"exp":1794295629}`, want: 1794295629},
		{name: "missing expiry", payload: `{}`},
		{name: "null expiry", payload: `{"exp":null}`},
		{name: "string expiry", payload: `{"exp":"1794295629"}`},
		{name: "fractional expiry", payload: `{"exp":1794295629.5}`},
		{name: "negative expiry", payload: `{"exp":-1}`},
		{name: "zero expiry", payload: `{"exp":0}`},
		{name: "unbounded outer SSO value", payload: `{"exp":9223372036854775807}`},
		{name: "invalid JSON", payload: `{sensitive-invalid-json`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Decode only the JWT scheduling claim; never return payload contents in errors")
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(tc.payload)) + ".signature"
			expiry, err := tokenExpiry(token)
			if tc.want != 0 {
				if err != nil || expiry.Unix() != tc.want {
					t.Fatalf("unexpected expiry: %s error=%v", expiry, err)
				}
			} else if err == nil || !expiry.IsZero() || strings.Contains(err.Error(), tc.payload) {
				t.Fatalf("invalid expiry was accepted or leaked: expiry=%s error=%v", expiry, err)
			}
		})
	}
	for _, token := range []string{"opaque-sensitive-token", "header.!.signature"} {
		if _, err := tokenExpiry(token); err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("opaque or malformed token was accepted or leaked")
		}
	}
}

func TestReconnectDeadline(t *testing.T) {
	acquiredAt := time.Unix(1794278349, 0)
	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		leadTime time.Duration
	}{
		{name: "deployment JWT", lifetime: 4*time.Hour + 48*time.Minute, leadTime: 28*time.Minute + 48*time.Second},
		{name: "one hour JWT", lifetime: time.Hour, leadTime: 6 * time.Minute},
		{name: "short JWT", lifetime: 2 * time.Minute, leadTime: 12 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Check the exact expiry-derived boundary without sleeping")
			conn := &Connection{ssoToken: "cached", ssoTokenAcquiredAt: acquiredAt, ssoTokenExpiresAt: acquiredAt.Add(tc.lifetime)}
			renewAt := conn.ssoTokenExpiresAt.Add(-tc.leadTime)
			for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond, tc.leadTime} {
				due, err := conn.tokenReconnectDue(renewAt.Add(offset))
				if err != nil || due != (offset >= 0) {
					t.Fatalf("unexpected boundary at offset %s: due=%v error=%v", offset, due, err)
				}
			}
		})
	}
	conn := &Connection{ssoLock: &sync.RWMutex{}, ssoToken: "opaque-sensitive-token", ssoTokenAcquiredAt: acquiredAt}
	t.Log("Unknown expiry cannot silently fall back to an assumed lifetime")
	if _, err := conn.TokenExpiry(); err == nil {
		t.Fatal("unknown expiry was not reported")
	}
	if renewed, err := conn.ReconnectDue(time.Now()); err == nil || renewed {
		t.Fatal("renewal guessed an opaque token lifetime")
	}
}

func TestReconnectUsesJWTIssuedAt(t *testing.T) {
	t.Log("Use JWT issuance rather than response receipt when computing 90 percent of lifetime")
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1794278349,"exp":1794295629}`)) + ".signature"
	issuedAt, expiresAt, err := tokenTimes(token)
	if err != nil {
		t.Fatal(err)
	}
	conn := &Connection{
		ssoToken: token, ssoTokenIssuedAt: issuedAt,
		ssoTokenAcquiredAt: issuedAt.Add(time.Minute), ssoTokenExpiresAt: expiresAt,
	}
	renewAt := issuedAt.Add(4*time.Hour + 19*time.Minute + 12*time.Second)
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		due, err := conn.tokenReconnectDue(renewAt.Add(offset))
		if err != nil || due != (offset >= 0) {
			t.Fatalf("unexpected JWT lifetime boundary: offset=%s due=%v error=%v", offset, due, err)
		}
	}
}

func TestCachedTokenReadersShareLock(t *testing.T) {
	conn := &Connection{
		ssoLock:            &sync.RWMutex{},
		ssoToken:           "cached-token",
		ssoTokenAcquiredAt: time.Now(),
		ssoTokenExpiresAt:  time.Now().Add(time.Hour),
	}
	t.Log("Cached authentication and not-due renewal complete while another reader holds the lock")
	conn.ssoLock.RLock()
	defer conn.ssoLock.RUnlock()
	results := make(chan error, 2)
	go func() {
		token, err := conn.authenticate()
		if err == nil && token != "cached-token" {
			err = fmt.Errorf("unexpected cached token")
		}
		results <- err
	}()
	go func() {
		renewed, err := conn.ReconnectDue(time.Now())
		if err == nil && renewed {
			err = fmt.Errorf("unexpected early renewal")
		}
		results <- err
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for n := 0; n < 2; n++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-deadline.C:
			t.Fatal("cached-token read tried to acquire an exclusive lock")
		}
	}
}

func TestReconnectConfiguredDeadline(t *testing.T) {
	issuedAt := time.Unix(1794278349, 0)
	acquiredAt := issuedAt.Add(time.Minute)
	for _, tc := range []struct {
		name     string
		policy   ReconnectPolicy
		deadline time.Time
		opaque   bool
	}{
		{"percentage 50", ReconnectPolicy{LifetimePercentage: 50}, issuedAt.Add(5 * time.Minute), false},
		{"percentage 1", ReconnectPolicy{LifetimePercentage: 1}, issuedAt.Add(6 * time.Second), false},
		{"percentage 99", ReconnectPolicy{LifetimePercentage: 99}, issuedAt.Add(594 * time.Second), false},
		{"fixed interval from acquisition", ReconnectPolicy{Interval: 3 * time.Minute}, acquiredAt.Add(3 * time.Minute), false},
		{"fixed interval with opaque token", ReconnectPolicy{Interval: 3 * time.Minute}, acquiredAt.Add(3 * time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Check configured scheduling immediately before, at, and after the exact deadline")
			conn := &Connection{ssoLock: &sync.RWMutex{}, ssoToken: "cached", ssoTokenIssuedAt: issuedAt, ssoTokenAcquiredAt: acquiredAt}
			if !tc.opaque {
				conn.ssoTokenExpiresAt = issuedAt.Add(10 * time.Minute)
			}
			for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
				due, err := conn.ReconnectDue(tc.deadline.Add(offset), tc.policy)
				if err != nil || due != (offset >= 0) {
					t.Fatalf("offset=%s due=%v error=%v", offset, due, err)
				}
			}
			conn.ssoToken = ""
			if due, err := conn.ReconnectDue(tc.deadline, tc.policy); err != nil || due {
				t.Fatal("unauthenticated connection must remain lazy")
			}
		})
	}
}

func TestReconnectPolicyValidation(t *testing.T) {
	conn := &Connection{ssoLock: &sync.RWMutex{}}
	for _, policy := range []ReconnectPolicy{
		{}, {Interval: -time.Second}, {LifetimePercentage: -1}, {LifetimePercentage: 100},
		{Interval: time.Minute, LifetimePercentage: 90},
	} {
		t.Logf("Reject invalid policy before accessing authentication: %+v", policy)
		if due, err := conn.ReconnectDue(time.Now(), policy); err == nil || due {
			t.Fatalf("accepted invalid policy %+v", policy)
		}
	}
	if _, err := conn.ReconnectDue(time.Now(), ReconnectPolicy{Interval: time.Minute}, ReconnectPolicy{Interval: time.Hour}); err == nil {
		t.Fatal("accepted multiple policies")
	}
}
