package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TheDarkGuardian/WireWall/internal/model"
)

const testOperatorToken = "test-operator-token-which-is-not-a-real-secret"

func newHTTPTest(t *testing.T) (*HTTPServer, http.Handler, *Service) {
	t.Helper()
	s := newTestService(t, "lab")
	h := NewHTTP(s, testOperatorToken, t.TempDir())
	return h, h.Handler(), s
}

func apiRequest(handler http.Handler, method, path string, body []byte, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://wirewall.test"+path, bytes.NewReader(body))
	r.RemoteAddr = "192.0.2.10:54321"
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func authHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + testOperatorToken}
}

func jsonBody(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHTTPRequiresExactAuthentication(t *testing.T) {
	_, handler, _ := newHTTPTest(t)
	for _, test := range []struct {
		name, authorization string
		want                int
	}{
		{"missing", "", 401},
		{"wrong bearer", "Bearer wrong-token", 401},
		{"raw token is not bearer", testOperatorToken, 401},
		{"different scheme", "Basic " + testOperatorToken, 401},
		{"valid bearer", "Bearer " + testOperatorToken, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, map[string]string{"Authorization": test.authorization})
			if w.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, test.want, w.Body)
			}
		})
	}
	w := apiRequest(handler, "GET", "/api/v1/health", nil, nil)
	if w.Code != 200 || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("health/security headers: %+v", w.Result())
	}
}

func TestHTTPRejectsCrossOriginAndMalformedOrigins(t *testing.T) {
	_, handler, _ := newHTTPTest(t)
	for _, test := range []struct {
		origin string
		want   int
	}{
		{"", 200}, {"http://wirewall.test", 200},
		{"http://attacker.test", 403}, {"null", 403},
		{"https://wirewall.test", 403}, {"http://wirewall.test/path", 403},
		{"http://wirewall.test?query=1", 403}, {"http://wirewall.test#fragment", 403},
		{"http://user@wirewall.test", 403},
	} {
		t.Run(test.origin, func(t *testing.T) {
			headers := authHeaders()
			headers["Origin"] = test.origin
			w := apiRequest(handler, "GET", "/api/v1/policy", nil, headers)
			if w.Code != test.want {
				t.Fatalf("origin %q status = %d, want %d", test.origin, w.Code, test.want)
			}
		})
	}
}

func TestHTTPSessionCookieAndCSRF(t *testing.T) {
	_, handler, service := newHTTPTest(t)
	w := apiRequest(handler, "POST", "/api/v1/session", jsonBody(t, map[string]string{"token": testOperatorToken}), nil)
	if w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	var login struct {
		Authenticated bool   `json:"authenticated"`
		CSRFToken     string `json:"csrfToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if !login.Authenticated || login.CSRFToken == "" {
		t.Fatalf("login = %+v", login)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("unsafe session cookie: %+v", cookies)
	}
	if w = apiRequest(handler, "GET", "/api/v1/snapshot", nil, nil, cookies[0]); w.Code != 200 {
		t.Fatalf("cookie read: %d", w.Code)
	}
	p := service.Policy()
	body := jsonBody(t, map[string]any{"policy": p, "expectedVersion": p.Version})
	if w = apiRequest(handler, "PUT", "/api/v1/policy", body, nil, cookies[0]); w.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", w.Code)
	}
	if w = apiRequest(handler, "PUT", "/api/v1/policy", body, map[string]string{"X-WireWall-CSRF": "wrong"}, cookies[0]); w.Code != 403 {
		t.Fatalf("wrong CSRF accepted: %d", w.Code)
	}
	if w = apiRequest(handler, "PUT", "/api/v1/policy", body, map[string]string{"X-WireWall-CSRF": login.CSRFToken}, cookies[0]); w.Code != 200 {
		t.Fatalf("valid CSRF rejected: %d %s", w.Code, w.Body)
	}
	if service.Policy().Version != p.Version+1 {
		t.Fatal("valid cookie mutation did not apply")
	}
	if w = apiRequest(handler, "DELETE", "/api/v1/session", nil, map[string]string{"X-WireWall-CSRF": login.CSRFToken}, cookies[0]); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w = apiRequest(handler, "GET", "/api/v1/snapshot", nil, nil, cookies[0]); w.Code != 401 {
		t.Fatalf("logged out cookie accepted: %d", w.Code)
	}
}

func TestHTTPExpiredSessionIsRejected(t *testing.T) {
	h, handler, _ := newHTTPTest(t)
	h.sessions["expired"] = session{csrf: "csrf", expires: time.Now().Add(-time.Minute)}
	w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, nil, &http.Cookie{Name: "wirewall_session", Value: "expired"})
	if w.Code != 401 {
		t.Fatalf("expired session status = %d", w.Code)
	}
}

func TestHTTPJSONContractAndPolicyConflict(t *testing.T) {
	_, handler, service := newHTTPTest(t)
	for _, body := range [][]byte{
		[]byte(`{"token":"x","unexpected":true}`),
		[]byte(`{"token":"x"} {"token":"y"}`),
		[]byte(`{"token":`),
		[]byte(`{"token":"` + strings.Repeat("x", 1<<20) + `"}`),
	} {
		w := apiRequest(handler, "POST", "/api/v1/session", body, nil)
		if w.Code != 400 {
			t.Fatalf("invalid JSON status = %d; body=%s", w.Code, w.Body)
		}
	}
	p := service.Policy()
	p.Mode = "enforce"
	body := jsonBody(t, map[string]any{"policy": p, "expectedVersion": p.Version})
	w := apiRequest(handler, "PUT", "/api/v1/policy", body, authHeaders())
	if w.Code != 200 {
		t.Fatalf("apply: %d %s", w.Code, w.Body)
	}
	w = apiRequest(handler, "PUT", "/api/v1/policy", body, authHeaders())
	if w.Code != 409 {
		t.Fatalf("stale write: %d %s", w.Code, w.Body)
	}
	current := service.Policy()
	invalid := current
	invalid.Mode = "invalid"
	w = apiRequest(handler, "PUT", "/api/v1/policy", jsonBody(t, map[string]any{"policy": invalid, "expectedVersion": current.Version}), authHeaders())
	if w.Code != 422 {
		t.Fatalf("invalid policy: %d %s", w.Code, w.Body)
	}
	if got := service.Policy(); got.Version != current.Version || got.Mode != current.Mode {
		t.Fatal("invalid policy changed active state")
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unknown"] = true
	w = apiRequest(handler, "PUT", "/api/v1/policy", jsonBody(t, raw), authHeaders())
	if w.Code != 400 {
		t.Fatalf("unknown mutation field accepted: %d", w.Code)
	}
}

func TestHTTPBanCreateAndDelete(t *testing.T) {
	_, handler, _ := newHTTPTest(t)
	w := apiRequest(handler, "POST", "/api/v1/bans", jsonBody(t, map[string]any{"address": "198.51.100.66", "reason": "Test scenario", "durationSeconds": 60}), authHeaders())
	if w.Code != 201 {
		t.Fatalf("create ban: %d %s", w.Code, w.Body)
	}
	var ban model.Ban
	if err := json.Unmarshal(w.Body.Bytes(), &ban); err != nil {
		t.Fatal(err)
	}
	w = apiRequest(handler, "DELETE", "/api/v1/bans/"+ban.ID, nil, authHeaders())
	if w.Code != 200 {
		t.Fatalf("delete ban: %d", w.Code)
	}
	w = apiRequest(handler, "DELETE", "/api/v1/bans/"+ban.ID, nil, authHeaders())
	if w.Code != 404 {
		t.Fatalf("missing ban: %d", w.Code)
	}
}

func TestHTTPLoginRateLimit(t *testing.T) {
	_, handler, _ := newHTTPTest(t)
	for i := 0; i < 10; i++ {
		w := apiRequest(handler, "POST", "/api/v1/session", []byte(`{"token":"incorrect"}`), nil)
		if w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := apiRequest(handler, "POST", "/api/v1/session", jsonBody(t, map[string]string{"token": testOperatorToken}), nil)
	if w.Code != 429 {
		t.Fatalf("11th login attempt = %d; want 429", w.Code)
	}
}

func TestHTTPStreamContainsExplicitLaboratoryIdentity(t *testing.T) {
	_, handler, _ := newHTTPTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "http://wirewall.test/api/v1/stream", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testOperatorToken)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream: %d %s", w.Code, w.Body)
	}
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("event: snapshot\n")) || !bytes.Contains(body, []byte(`"simulated":true`)) || !bytes.Contains(body, []byte(`"attached":false`)) {
		t.Fatalf("stream hides laboratory identity: %s", body)
	}
}
