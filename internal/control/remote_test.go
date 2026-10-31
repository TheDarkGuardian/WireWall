package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func handlerTransport(handler http.Handler, inspect func(*http.Request)) http.RoundTripper {
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if inspect != nil {
			inspect(request)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Result(), nil
	})
}

func trustedAgentHandler(service *Service) http.Handler {
	private := NewAgentHandler(service)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		private.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), agentSocketContextKey{}, true)))
	})
}

func TestAgentSurfaceIsNarrowAndHasNoBrowserSessions(t *testing.T) {
	service := newTestService(t, "lab")
	handler := trustedAgentHandler(service)
	for _, test := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/api/v1/session"}, {"POST", "/api/v1/session"}, {"DELETE", "/api/v1/session"},
		{"POST", "/api/v1/lab/reset"}, {"POST", "/api/v1/lab/scenarios"},
		{"GET", "/api/v1/unknown"}, {"PUT", "/api/v1/stream"},
		{"DELETE", "/api/v1/bans/../../policy"}, {"DELETE", "/api/v1/bans/not-a-ban-id"},
	} {
		w := apiRequest(handler, test.method, test.path, nil, authHeaders())
		if w.Code != http.StatusNotFound {
			t.Fatalf("%s %s exposed by agent: %d", test.method, test.path, w.Code)
		}
	}
	// The private transport boundary authorizes this request, not any browser
	// cookie or external operator token. Those headers are discarded.
	w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, map[string]string{
		"Authorization": "Bearer unrelated-browser-secret", "Cookie": "wirewall_session=unrelated", "Origin": "http://external.invalid",
	})
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"backend":"lab"`)) {
		t.Fatalf("private agent request failed: %d %s", w.Code, w.Body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("root agent created a browser cookie")
	}
	w = apiRequest(handler, "GET", "/api/v1/policy", nil, nil)
	if w.Code != 200 {
		t.Fatalf("private policy read: %d %s", w.Code, w.Body)
	}
}

func TestProxyRequiresPublicAuthAndStripsCredentials(t *testing.T) {
	service := newTestService(t, "lab")
	var calls int
	transport := handlerTransport(trustedAgentHandler(service), func(request *http.Request) {
		calls++
		for _, name := range []string{"Authorization", "Cookie", "Origin", "X-WireWall-CSRF", "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if value := request.Header.Get(name); value != "" {
				t.Errorf("browser header leaked to private agent: %s=%q", name, value)
			}
		}
		if request.URL.Host != "wirewall.internal" || request.Host != "wirewall.internal" {
			t.Errorf("unexpected private target: %s %s", request.URL.Host, request.Host)
		}
	})
	h := newProxyHTTP(testOperatorToken, t.TempDir(), transport)
	handler := h.Handler()
	if w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, nil); w.Code != 401 || calls != 0 {
		t.Fatalf("unauthenticated proxy reached agent: %d calls=%d", w.Code, calls)
	}
	headers := authHeaders()
	headers["Origin"] = "http://wirewall.test"
	headers["Cookie"] = "wirewall_session=unrelated"
	headers["X-WireWall-CSRF"] = "browser-only"
	headers["Forwarded"] = "host=attacker.invalid"
	headers["X-Forwarded-For"] = "198.51.100.4"
	w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, headers)
	if w.Code != 200 || calls != 1 {
		t.Fatalf("authenticated proxy failed: %d calls=%d body=%s", w.Code, calls, w.Body)
	}
	headers["Origin"] = "http://attacker.invalid"
	w = apiRequest(handler, "GET", "/api/v1/snapshot", nil, headers)
	if w.Code != 403 || calls != 1 {
		t.Fatalf("cross-origin proxy reached agent: %d calls=%d", w.Code, calls)
	}
}

func TestProxySessionAndCSRFStayInWebProcess(t *testing.T) {
	service := newTestService(t, "lab")
	var calls int
	h := newProxyHTTP(testOperatorToken, t.TempDir(), handlerTransport(trustedAgentHandler(service), func(*http.Request) { calls++ }))
	handler := h.Handler()
	w := apiRequest(handler, "POST", "/api/v1/session", jsonBody(t, map[string]string{"token": testOperatorToken}), nil)
	if w.Code != 200 || calls != 0 {
		t.Fatalf("login forwarded to root: %d calls=%d", w.Code, calls)
	}
	var result struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	p := service.Policy()
	body := jsonBody(t, map[string]any{"policy": p, "expectedVersion": p.Version})
	w = apiRequest(handler, "PUT", "/api/v1/policy", body, nil, cookie)
	if w.Code != 403 || calls != 0 {
		t.Fatalf("CSRF-less mutation forwarded to root: %d calls=%d", w.Code, calls)
	}
	w = apiRequest(handler, "PUT", "/api/v1/policy", body, map[string]string{"X-WireWall-CSRF": result.CSRFToken}, cookie)
	if w.Code != 200 || calls != 1 || service.Policy().Version != p.Version+1 {
		t.Fatalf("valid mutation did not reach root: %d calls=%d %s", w.Code, calls, w.Body)
	}
	w = apiRequest(handler, "DELETE", "/api/v1/session", nil, map[string]string{"X-WireWall-CSRF": result.CSRFToken}, cookie)
	if w.Code != 200 || calls != 1 {
		t.Fatalf("logout forwarded to root: %d calls=%d", w.Code, calls)
	}
	if w = apiRequest(handler, "GET", "/api/v1/policy", nil, nil, cookie); w.Code != 401 {
		t.Fatalf("logged-out proxy cookie accepted: %d", w.Code)
	}
}

func TestProxyPreservesNarrowSurfaceBodyLimitAndUnavailableState(t *testing.T) {
	var calls int
	h := newProxyHTTP(testOperatorToken, t.TempDir(), roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("dial unix /private/privileged/path: permission denied")
	}))
	handler := h.Handler()
	w := apiRequest(handler, "POST", "/api/v1/lab/reset", nil, authHeaders())
	if w.Code != 404 || calls != 0 {
		t.Fatalf("proxy exposed unsupported agent path: %d calls=%d", w.Code, calls)
	}
	w = apiRequest(handler, "PUT", "/api/v1/policy", []byte(strings.Repeat("x", agentRequestBodyLimit+1)), authHeaders())
	if w.Code != 413 || calls != 0 {
		t.Fatalf("oversized proxy request forwarded: %d calls=%d", w.Code, calls)
	}
	w = apiRequest(handler, "GET", "/api/v1/snapshot", nil, authHeaders())
	if w.Code != 503 || calls != 1 || strings.Contains(w.Body.String(), "/private/") {
		t.Fatalf("unavailable agent not handled safely: %d calls=%d %s", w.Code, calls, w.Body)
	}
	// Proxy mode has no in-process Service. Its unauthenticated liveness route
	// must query the agent without dereferencing a nil service.
	w = apiRequest(handler, "GET", "/api/v1/health", nil, nil)
	if w.Code != 503 || calls != 2 {
		t.Fatalf("proxy health: %d calls=%d", w.Code, calls)
	}
}

func TestAgentRejectsOversizedAndUnknownMutationFields(t *testing.T) {
	service := newTestService(t, "lab")
	handler := trustedAgentHandler(service)
	for _, body := range [][]byte{
		[]byte(`{"address":"198.51.100.9","reason":"test","durationSeconds":60,"shell":"echo bad"}`),
		[]byte(`{"address":"198.51.100.9","reason":"` + strings.Repeat("x", agentRequestBodyLimit) + `","durationSeconds":60}`),
	} {
		w := apiRequest(handler, "POST", "/api/v1/bans", body, nil)
		if w.Code != 400 || len(service.Bans()) != 0 {
			t.Fatalf("invalid private mutation accepted: %d %s", w.Code, w.Body)
		}
	}
}

func TestProxyStreamStopsAtCookieExpiry(t *testing.T) {
	var calls atomic.Int32
	h := newProxyHTTP(testOperatorToken, t.TempDir(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-request.Context().Done()
		return nil, request.Context().Err()
	}))
	h.sessions["expiring"] = session{csrf: "csrf", expires: time.Now().Add(40 * time.Millisecond)}
	start := time.Now()
	w := apiRequest(h.Handler(), "GET", "/api/v1/stream", nil, nil, &http.Cookie{Name: "wirewall_session", Value: "expiring"})
	if calls.Load() != 1 || time.Since(start) > time.Second || w.Code != 503 {
		t.Fatalf("stream failed to stop at session deadline: status=%d calls=%d elapsed=%s", w.Code, calls.Load(), time.Since(start))
	}
}

func TestAgentHandlerCannotBeMountedOnPublicTCPByMistake(t *testing.T) {
	handler := NewAgentHandler(newTestService(t, "lab"))
	w := apiRequest(handler, "GET", "/api/v1/snapshot", nil, authHeaders())
	if w.Code != http.StatusForbidden {
		t.Fatalf("agent handler accepted a request without a Unix socket context: %d", w.Code)
	}
}

func TestProxyStreamStopsAfterLogout(t *testing.T) {
	started := make(chan struct{})
	h := newProxyHTTP(testOperatorToken, t.TempDir(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		return nil, request.Context().Err()
	}))
	h.sessions["active"] = session{csrf: "csrf", expires: time.Now().Add(time.Hour)}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		apiRequest(h.Handler(), "GET", "/api/v1/stream", nil, nil, &http.Cookie{Name: "wirewall_session", Value: "active"})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("proxy stream did not start")
	}
	h.mu.Lock()
	delete(h.sessions, "active")
	h.mu.Unlock()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy stream survived logout")
	}
}

func TestProxyStripsRootCookiesAndFlushesSSE(t *testing.T) {
	h := newProxyHTTP(testOperatorToken, t.TempDir(), roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{
			"Content-Type": {"text/event-stream"}, "Set-Cookie": {"root-cookie=bad"},
		}, Body: io.NopCloser(strings.NewReader("event: snapshot\ndata: {}\n\n")), Request: request}, nil
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("GET", "http://wirewall.test/api/v1/stream", nil).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+testOperatorToken)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !w.Flushed || w.Header().Get("Set-Cookie") != "" || !strings.Contains(w.Body.String(), "event: snapshot") {
		t.Fatalf("SSE proxy fidelity: status=%d flushed=%v cookies=%q body=%s", w.Code, w.Flushed, w.Header().Get("Set-Cookie"), w.Body)
	}
}
