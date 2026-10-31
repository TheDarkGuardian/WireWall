package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const agentRequestBodyLimit = 1 << 20

type agentSocketContextKey struct{}

// NewAgentHandler is only for a private, permission-protected Unix listener.
// Socket ownership and directory permissions are its authentication boundary;
// it must never be mounted on a TCP listener. It exposes no login, static-file,
// laboratory or arbitrary-command surface.
func NewAgentHandler(service *Service) http.Handler {
	internalToken := newID() + newID()
	local := NewHTTP(service, internalToken, "").Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trusted, _ := r.Context().Value(agentSocketContextKey{}).(bool); !trusted {
			fail(w, http.StatusForbidden, errors.New("agent API yalnız özel Unix socket üzerinden kullanılabilir"))
			return
		}
		if !allowedAgentRequest(r.Method, r.URL.Path) {
			fail(w, http.StatusNotFound, errors.New("agent API yolu bulunamadı"))
			return
		}
		request := r.Clone(r.Context())
		request.Header = r.Header.Clone()
		stripRemoteCredentials(request.Header)
		request.Header.Set("Authorization", "Bearer "+internalToken)
		request.Body = http.MaxBytesReader(w, r.Body, agentRequestBodyLimit)
		local.ServeHTTP(w, request)
	})
}

// NewProxyHTTP builds the unprivileged browser/API process. The operator key and
// browser cookies stay in this process; neither is forwarded to the root agent.
func NewProxyHTTP(token, socketPath, webDir string) *HTTPServer {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:    true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return newProxyHTTP(token, webDir, transport)
}

// The transport parameter permits deterministic proxy tests without starting a
// privileged Unix listener or invoking any Linux networking command.
func newProxyHTTP(token, webDir string, transport http.RoundTripper) *HTTPServer {
	h := NewHTTP(nil, token, webDir)
	target := &url.URL{Scheme: "http", Host: "wirewall.internal"}
	h.remote = &httputil.ReverseProxy{
		Rewrite: func(proxy *httputil.ProxyRequest) {
			proxy.SetURL(target)
			proxy.Out.Host = target.Host
			stripRemoteCredentials(proxy.Out.Header)
			// The browser origin has already been checked by the public HTTP
			// handler. It has no meaning across the private Unix boundary.
			for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				proxy.Out.Header.Del(name)
			}
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			// Keep Unix paths and privileged-process details out of public errors.
			fail(w, http.StatusServiceUnavailable, errors.New("firewall agent erişilemiyor"))
		},
		ModifyResponse: func(response *http.Response) error {
			// The root process never creates browser sessions. Defensively drop
			// accidental upstream cookies rather than adopting them publicly.
			response.Header.Del("Set-Cookie")
			return nil
		},
	}
	return h
}

func stripRemoteCredentials(header http.Header) {
	for _, name := range []string{"Origin", "Cookie", "Authorization", "X-WireWall-CSRF"} {
		header.Del(name)
	}
}

func allowedAgentRequest(method, path string) bool {
	switch method + " " + path {
	case "GET /api/v1/health", "GET /api/v1/snapshot", "GET /api/v1/stream", "GET /api/v1/policy", "GET /api/v1/audit", "GET /api/v1/events", "GET /api/v1/events/export",
		"POST /api/v1/policy/validate", "PUT /api/v1/policy", "POST /api/v1/policy/confirm", "POST /api/v1/bans":
		return true
	}
	if method != http.MethodDelete || !strings.HasPrefix(path, "/api/v1/bans/") {
		return false
	}
	id := strings.TrimPrefix(path, "/api/v1/bans/")
	if len(id) != 24 {
		return false
	}
	for _, character := range id {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func (h *HTTPServer) proxyAPI(w http.ResponseWriter, r *http.Request) {
	if !allowedAgentRequest(r.Method, r.URL.Path) {
		fail(w, http.StatusNotFound, errors.New("API yolu bulunamadı"))
		return
	}
	if r.ContentLength > agentRequestBodyLimit {
		fail(w, http.StatusRequestEntityTooLarge, errors.New("istek gövdesi kapasite sınırını aştı"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, agentRequestBodyLimit)
	if r.URL.Path != "/api/v1/stream" {
		h.remote.ServeHTTP(w, r)
		return
	}
	// Authentication is checked at stream entry, then rechecked while a cookie
	// stream is open. Logout/expiry must not leave a root-agent stream alive.
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") && h.validToken(strings.TrimPrefix(authorization, "Bearer ")) {
		h.remote.ServeHTTP(w, r)
		return
	}
	session, ok := h.getSession(r)
	if !ok {
		fail(w, http.StatusUnauthorized, errors.New("oturum gerekli"))
		return
	}
	ctx, cancel := context.WithDeadline(r.Context(), session.expires)
	defer cancel()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, valid := h.getSession(r); !valid {
					cancel()
					return
				}
			}
		}
	}()
	h.remote.ServeHTTP(w, r.WithContext(ctx))
}
