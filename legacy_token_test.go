package ovirtsdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLegacyTokenExpiryMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      int64
	}{
		{"engine string milliseconds", `"1795466307123"`, 1795466307123},
		{"numeric milliseconds", `1795466307123`, 1795466307123},
		{"unbounded", `"9223372036854775807"`, 0},
		{"overflow", `9223372036854775808`, 0},
		{"missing", ``, 0},
		{"null", `null`, 0},
		{"zero", `0`, 0},
		{"negative", `-1`, 0},
		{"fractional", `1795466307123.5`, 0},
		{"malformed", `"secret-invalid-expiry"`, 0},
		{"object", `{}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Log("Read epoch milliseconds without assuming a token lifetime")
			got := legacyTokenExpiry(json.RawMessage(tc.raw))
			if tc.want == 0 {
				if !got.IsZero() {
					t.Fatal("invalid metadata produced a deadline")
				}
			} else if got.UnixNano()/int64(time.Millisecond) != tc.want {
				t.Fatalf("incorrect millisecond deadline: %s", got)
			}
		})
	}
}

func TestLegacyAuthenticationSchedulesAndPublishesExpiry(t *testing.T) {
	for _, jwt := range []bool{false, true} {
		t.Run(fmt.Sprintf("jwt=%v", jwt), func(t *testing.T) {
			deadline := time.Now().Add(time.Hour).Truncate(time.Millisecond)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := "opaque-sensitive-token"
				if jwt {
					token = renewalTestToken(deadline.Add(-time.Minute), 1)
				}
				fmt.Fprintf(w, `{"access_token":%q,"exp":%q}`, token, fmt.Sprint(deadline.UnixNano()/int64(time.Millisecond)))
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
			if err := conn.Authenticate(); err != nil {
				t.Fatal(err)
			}
			expiry, err := conn.TokenExpiry()
			want := deadline
			if jwt {
				want = deadline.Add(-time.Minute).Truncate(time.Second)
			}
			if err != nil || !expiry.Equal(want) {
				t.Fatalf("incorrect expiry: %s error=%v", expiry, err)
			}
			t.Log("Check the default 90 percent boundary and publication to existing connections")
			lifetime := expiry.Sub(conn.ssoTokenAcquiredAt)
			renewAt := expiry.Add(-(lifetime/100*10 + lifetime%100*10/100))
			for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
				due, err := conn.ReconnectDue(renewAt.Add(offset))
				if err != nil || due != (offset >= 0) {
					t.Fatalf("incorrect renewal boundary: %s %v %v", offset, due, err)
				}
			}
			active := build()
			if err := active.ReplaceAuthentication(conn); err != nil {
				t.Fatal(err)
			}
			if got, err := active.TokenExpiry(); err != nil || !got.Equal(want) {
				t.Fatal("publication lost deadline")
			}
		})
	}
}
